"""HTTP-приложение шлюза: прокси модели/MCP, авторизация, observe, апрувы, аудит и дашборд."""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse

from .. import __version__
from ..approvals import ApprovalQueue
from ..audit import AuditLog
from ..demo import mcp_server, mock_llm
from ..demo.world import World
from ..engine import PolicyEngine
from ..env import load_dotenv
from ..policy import Policy, load_policy
from ..policy_draft import generate_policy_draft
from ..redteam import runner
from .auth import AuthConfig
from .providers import ProviderAdapter
from .proxy import DEMO, Gateway

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"


async def _read_json(request: Request) -> tuple[Any, JSONResponse | None]:
    try:
        return await request.json(), None
    except ValueError:
        return None, JSONResponse({"error": "Тело запроса должно быть корректным JSON"}, status_code=400)


def _http_verify() -> bool | str:
    ca_bundle = os.getenv("AXISEC_LLM_CA_BUNDLE", "").strip()
    if ca_bundle:
        return ca_bundle
    return os.getenv("AXISEC_LLM_VERIFY_TLS", "true").strip().lower() not in ("0", "false", "no")


def create_app(policy_path: str | None = None, audit_db: str | None = None, mode_override: str | None = None) -> FastAPI:
    load_dotenv()
    policy_file = Path(policy_path or os.getenv("AXISEC_POLICY") or ROOT / "policies" / "crm_agent.yaml")
    llm_provider = os.getenv("AXISEC_LLM_PROVIDER", "")
    llm_upstream = os.getenv("AXISEC_LLM_UPSTREAM", DEMO)
    mcp_upstreams = json.loads(os.getenv("AXISEC_MCP_UPSTREAMS", "") or '{"crm": "demo"}')
    provider = ProviderAdapter(llm_upstream, provider=llm_provider, api_key=os.getenv("AXISEC_LLM_API_KEY", ""))
    verify_tls = _http_verify()
    observe_override = (mode_override or os.getenv("AXISEC_MODE", "")).strip().lower() or None
    auth = AuthConfig()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.http.is_closed:
            app.state.http = httpx.AsyncClient(timeout=60, verify=verify_tls)
            app.state.gateway.http = app.state.http
        yield
        await app.state.http.aclose()
        app.state.audit.close()

    app = FastAPI(title="Axisec", version=__version__, docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
    app.state.policy_file = policy_file
    app.state.auth = auth
    app.state.engine = PolicyEngine(load_policy(policy_file), observe_override=observe_override)
    app.state.audit = AuditLog(audit_db or os.getenv("AXISEC_AUDIT_DB") or None)
    app.state.approvals = ApprovalQueue(on_change=lambda item: app.state.audit.publish({"type": "approval", **item}))
    app.state.world = World()
    app.state.http = httpx.AsyncClient(timeout=60, verify=verify_tls)
    app.state.gateway = Gateway(
        app.state.engine,
        app.state.audit,
        app.state.world,
        app.state.http,
        llm_upstream=provider.upstream,
        llm_api_key=os.getenv("AXISEC_LLM_API_KEY", ""),
        mcp_upstreams=mcp_upstreams,
        llm_provider=provider.provider,
        provider_adapter=provider,
        approvals=app.state.approvals,
    )

    def _hdrs(request: Request) -> dict[str, str]:
        return {k.lower(): v for k, v in request.headers.items()}

    def _require_admin(request: Request, query_token: str = "") -> JSONResponse | None:
        if not app.state.auth.check_admin(_hdrs(request), query_token):
            return JSONResponse({"error": "Требуется токен администратора Axisec"}, status_code=401)
        return None

    def _check_gateway(request: Request) -> tuple[JSONResponse | None, str, str]:
        """Возвращает `(ошибка_401 | None, роль, auth_для_апстрима)`."""
        hdrs = _hdrs(request)
        ok, bound_role = app.state.auth.check_gateway(hdrs)
        if not ok:
            return JSONResponse({"error": {"message": "Требуется токен шлюза Axisec", "type": "axisec_auth"}}, status_code=401), "", ""
        role = bound_role or request.headers.get("x-axisec-role", "").strip()
        # Не пересылаем токен самого Axisec во внешнюю LLM, если он пришёл в Authorization без X-Axisec-Key
        upstream_auth = request.headers.get("authorization", "")
        if app.state.auth.gateway_enabled and "x-axisec-key" not in hdrs:
            upstream_auth = ""
        return None, role, upstream_auth

    def _wait_override(request: Request) -> float | None:
        raw = request.headers.get("x-axisec-approval-wait")
        if raw is None or not raw.strip():
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None

    def session_of(request: Request) -> str:
        return request.headers.get("x-axisec-session", "")

    # ------------------------------------------------------------ точки контроля
    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        err, role, upstream_auth = _check_gateway(request)
        if err is not None:
            return err
        body, jerr = await _read_json(request)
        if jerr is not None:
            return jerr
        if not isinstance(body, dict):
            return JSONResponse({"error": "Ожидался JSON-объект"}, status_code=400)
        wait_ov = _wait_override(request)
        if body.get("stream"):
            status, res = await app.state.gateway.chat_stream(
                body, session_of(request), upstream_auth, role=role, wait_override=wait_ov
            )
            if status != 200:
                return JSONResponse(res, status_code=status)
            return StreamingResponse(res, media_type="text/event-stream", headers={"cache-control": "no-cache"})
        status, resp = await app.state.gateway.chat(
            body, session_of(request), upstream_auth, role=role, wait_override=wait_ov
        )
        return JSONResponse(resp, status_code=status)

    @app.post("/mcp/{server}")
    async def mcp_proxy(server: str, request: Request):
        err, role, _ = _check_gateway(request)
        if err is not None:
            return err
        payload, jerr = await _read_json(request)
        if jerr is not None:
            return jerr
        status, resp, extra = await app.state.gateway.mcp(
            server, payload, session_of(request), dict(request.headers), role=role, wait_override=_wait_override(request)
        )
        if resp is None:
            return Response(status_code=status, headers=extra)
        return JSONResponse(resp, status_code=status, headers=extra)

    @app.get("/mcp/{server}")
    async def mcp_stream(server: str, request: Request):
        err, _, _ = _check_gateway(request)
        if err is not None:
            return err
        status, stream_iter, extra = await app.state.gateway.mcp_stream(server, dict(request.headers))
        if stream_iter is None:
            return Response(status_code=status, headers=extra)
        return StreamingResponse(stream_iter, status_code=status, media_type="text/event-stream", headers=extra)

    # ------------------------------------------------------------ стенд без защиты
    @app.post("/demo/llm/v1/chat/completions")
    async def demo_llm(request: Request):
        return JSONResponse(mock_llm.complete(await request.json()))

    @app.post("/demo/mcp")
    async def demo_mcp(request: Request):
        resp = mcp_server.handle(app.state.world, await request.json())
        return Response(status_code=202) if resp is None else JSONResponse(resp)

    @app.get("/demo/mcp")
    async def demo_mcp_no_stream():
        return Response(status_code=405, headers={"allow": "POST"})

    # ------------------------------------------------------------ API дашборда
    @app.get("/api/health")
    async def health():
        eng = app.state.engine
        p = eng.policy
        gw = app.state.gateway
        return {
            "status": "ok",
            "version": __version__,
            "policy": p.name,
            "mode": "observe" if eng.is_observe else "enforce",
            "tools": len(p.tools),
            "roles": sorted(p.roles),
            "llm_upstream": gw.provider.upstream,
            "llm_provider": gw.provider.provider,
            "mcp_servers": sorted(mcp_upstreams),
            "auth_required": app.state.auth.admin_enabled,
            "gateway_auth_required": app.state.auth.gateway_enabled,
            "pending_approvals": len(app.state.approvals.list("pending")),
        }

    @app.get("/api/events")
    async def events(
        request: Request,
        limit: int = 200,
        action: str = "",
        channel: str = "",
        tool: str = "",
        session: str = "",
        source: str = "",
    ):
        if (err := _require_admin(request)) is not None:
            return err
        return app.state.audit.events(min(limit, 1000), action=action, channel=channel, tool=tool, session=session, source=source)

    @app.get("/api/events/export")
    async def export_events(request: Request, format: str = "jsonl", limit: int = 1000):
        if (err := _require_admin(request)) is not None:
            return err
        lim = min(limit, 5000)
        if format.lower() == "cef":
            return PlainTextResponse(app.state.audit.export_cef(lim), media_type="text/plain; charset=utf-8")
        return PlainTextResponse(app.state.audit.export_jsonl(lim), media_type="application/x-ndjson; charset=utf-8")

    @app.post("/api/events/clear")
    async def clear_events(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        app.state.audit.clear()
        return {"ok": True}

    @app.get("/api/stats")
    async def stats(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        return app.state.audit.stats()

    @app.get("/metrics")
    async def metrics(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        pending = len(app.state.approvals.list("pending"))
        return PlainTextResponse(app.state.audit.prometheus_metrics(pending), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/stream")
    async def stream(request: Request, token: str = ""):
        if (err := _require_admin(request, token)) is not None:
            return err
        queue = app.state.audit.subscribe()

        max_secs_raw = os.getenv("AXISEC_STREAM_MAX_SECONDS")
        max_secs = float(max_secs_raw) if max_secs_raw else (25.0 if os.getenv("VERCEL") else 0.0)
        deadline = (time.monotonic() + max_secs) if max_secs > 0 else None

        async def gen():
            try:
                yield ": connected\n\n"
                while not await request.is_disconnected():
                    if deadline is not None and time.monotonic() > deadline:
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=10)
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                app.state.audit.unsubscribe(queue)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"cache-control": "no-cache"})

    @app.get("/api/policy")
    async def policy(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        eng = app.state.engine
        p = eng.policy
        return {
            "name": p.name,
            "description": p.description,
            "mode": "observe" if eng.is_observe else "enforce",
            "default_action": p.default_action,
            "roles": {n: {"description": r.description, "mode": r.mode, "deny_tools": r.deny_tools,
                          "allow_tools": r.allow_tools} for n, r in p.roles.items()},
            "yaml": policy_file.read_text(encoding="utf-8"),
            "tools": [{"name": n, "action": t.action, "description": t.description} for n, t in p.tools.items()],
        }

    @app.post("/api/policy/mode")
    async def set_policy_mode(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        body, jerr = await _read_json(request)
        if jerr is not None:
            return jerr
        mode = str((body or {}).get("mode", "")).strip().lower()
        if mode not in ("enforce", "observe"):
            return JSONResponse({"error": "mode должен быть enforce или observe"}, status_code=400)
        app.state.engine = PolicyEngine(app.state.engine.policy, observe_override=mode)
        app.state.gateway.engine = app.state.engine
        return {"ok": True, "mode": mode}

    @app.post("/api/policy/reload")
    async def reload_policy(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        body = {}
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                body = await request.json()
            except ValueError:
                body = {}
        try:
            if isinstance(body, dict) and body.get("yaml"):
                new_policy = Policy.model_validate(yaml.safe_load(str(body["yaml"])) or {})
            else:
                new_policy = load_policy(policy_file)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": f"Ошибка проверки политики: {exc}"}, status_code=400)
        ov = app.state.engine._observe_override
        app.state.engine = PolicyEngine(new_policy, observe_override=ov)
        app.state.gateway.engine = app.state.engine
        return {"ok": True, "policy": new_policy.name, "tools": len(new_policy.tools),
                "mode": "observe" if app.state.engine.is_observe else "enforce"}

    @app.post("/api/policy/draft")
    async def policy_draft(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        body = {}
        try:
            body = await request.json()
        except ValueError:
            body = {}
        tools = body.get("tools") if isinstance(body, dict) else None
        if tools is None:
            server = str((body or {}).get("server") or next(iter(mcp_upstreams)))
            try:
                tools = await app.state.gateway.list_upstream_tools(server)
            except KeyError:
                return JSONResponse({"error": f"MCP-сервер «{server}» не настроен"}, status_code=404)
        use_audit = bool((body or {}).get("use_audit", True))
        events_list = app.state.audit.events(500) if use_audit else []
        return generate_policy_draft(
            tools,
            name=str((body or {}).get("name") or "draft-policy"),
            mode=str((body or {}).get("mode") or "observe"),
            audit_events=events_list,
        )

    @app.get("/api/approvals")
    async def approvals_list(request: Request, status: str = ""):
        if (err := _require_admin(request)) is not None:
            return err
        return app.state.approvals.list(status)

    @app.post("/api/approvals/{item_id}/approve")
    async def approval_approve(item_id: str, request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        item = app.state.approvals.resolve(item_id, True)
        if item is None:
            return JSONResponse({"error": "Заявка не найдена"}, status_code=404)
        return item

    @app.post("/api/approvals/{item_id}/reject")
    async def approval_reject(item_id: str, request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        item = app.state.approvals.resolve(item_id, False)
        if item is None:
            return JSONResponse({"error": "Заявка не найдена"}, status_code=404)
        return item

    @app.post("/api/check")
    async def check(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        body, jerr = await _read_json(request)
        if jerr is not None:
            return jerr
        body = body if isinstance(body, dict) else {}
        role = str(body.get("role", "") or "").strip()
        d = app.state.engine.evaluate(str(body.get("tool", "")), body.get("args") or {}, role=role)
        app.state.audit.record(
            channel="check", tool=d.tool, args=body.get("args") or {}, action=d.action,
            rule=d.rule, reason=d.reason, owasp=d.owasp, latency_us=d.latency_us,
            session="manual", source=role,
        )
        return d.to_dict()

    @app.get("/api/demo/scenarios")
    async def scenarios(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        return [{k: s.get(k) for k in ("id", "kind", "title", "owasp", "prompt", "note")} for s in runner.SCENARIOS]

    @app.post("/api/demo/run")
    async def demo_run(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        body, jerr = await _read_json(request)
        if jerr is not None:
            return jerr
        body = body if isinstance(body, dict) else {}
        sc = runner.scenario(str(body.get("id", "")))
        if sc is None and body.get("prompt"):
            sc = {"id": "custom", "kind": "attack", "title": "Свой запрос", "prompt": str(body["prompt"])}
        if sc is None:
            return JSONResponse({"error": "Сценарий не найден"}, status_code=404)
        return await runner.run_scenario(app, sc, bool(body.get("protected", True)))

    @app.post("/api/redteam/run")
    async def redteam_run(request: Request):
        if (err := _require_admin(request)) is not None:
            return err
        return await runner.run_suite(app)

    @app.get("/")
    async def index():
        return FileResponse(DASHBOARD, media_type="text/html")

    return app
