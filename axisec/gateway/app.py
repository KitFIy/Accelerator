"""HTTP-приложение шлюза: прокси для модели и MCP, API аудита, стенд, дашборд."""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from .. import __version__
from ..audit import AuditLog
from ..demo import mcp_server, mock_llm
from ..demo.world import World
from ..engine import PolicyEngine
from ..policy import load_policy
from ..redteam import runner
from .providers import ProviderAdapter
from .proxy import DEMO, Gateway

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"


def _http_verify() -> bool | str:
    ca_bundle = os.getenv("AXISEC_LLM_CA_BUNDLE", "").strip()
    if ca_bundle:
        return ca_bundle
    return os.getenv("AXISEC_LLM_VERIFY_TLS", "true").strip().lower() not in ("0", "false", "no")


def create_app(policy_path: str | None = None, audit_db: str | None = None) -> FastAPI:
    policy_file = Path(policy_path or os.getenv("AXISEC_POLICY") or ROOT / "policies" / "crm_agent.yaml")
    llm_provider = os.getenv("AXISEC_LLM_PROVIDER", "")
    llm_upstream = os.getenv("AXISEC_LLM_UPSTREAM", DEMO)
    mcp_upstreams = json.loads(os.getenv("AXISEC_MCP_UPSTREAMS", "") or '{"crm": "demo"}')
    provider = ProviderAdapter(llm_upstream, provider=llm_provider, api_key=os.getenv("AXISEC_LLM_API_KEY", ""))
    verify_tls = _http_verify()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.http.is_closed:
            app.state.http = httpx.AsyncClient(timeout=60, verify=verify_tls)
            app.state.gateway.http = app.state.http
        yield
        await app.state.http.aclose()

    app = FastAPI(title="Axisec", version=__version__, docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
    app.state.policy_file = policy_file
    app.state.engine = PolicyEngine(load_policy(policy_file))
    app.state.audit = AuditLog(audit_db or os.getenv("AXISEC_AUDIT_DB") or None)
    app.state.world = World()
    app.state.http = httpx.AsyncClient(timeout=60, verify=verify_tls)
    app.state.gateway = Gateway(app.state.engine, app.state.audit, app.state.world, app.state.http,
                                llm_upstream=provider.upstream, llm_api_key=os.getenv("AXISEC_LLM_API_KEY", ""),
                                mcp_upstreams=mcp_upstreams, llm_provider=provider.provider,
                                provider_adapter=provider)

    def session_of(request: Request) -> str:
        return request.headers.get("x-axisec-session", "")

    # ------------------------------------------------------------ точки контроля
    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await request.json()
        status, resp = await app.state.gateway.chat(body, session_of(request),
                                                    request.headers.get("authorization", ""))
        if body.get("stream") and status == 200:
            return StreamingResponse(_as_sse(resp), media_type="text/event-stream")
        return JSONResponse(resp, status_code=status)

    @app.post("/mcp/{server}")
    async def mcp_proxy(server: str, request: Request):
        payload = await request.json()
        status, resp, extra = await app.state.gateway.mcp(server, payload, session_of(request),
                                                          dict(request.headers))
        if resp is None:
            return Response(status_code=status, headers=extra)
        return JSONResponse(resp, status_code=status, headers=extra)

    @app.get("/mcp/{server}")
    async def mcp_no_stream(server: str):
        return Response(status_code=405, headers={"allow": "POST"})

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
        p = app.state.engine.policy
        gw = app.state.gateway
        return {"status": "ok", "version": __version__, "policy": p.name, "tools": len(p.tools),
                "llm_upstream": gw.provider.upstream, "llm_provider": gw.provider.provider,
                "mcp_servers": sorted(mcp_upstreams)}

    @app.get("/api/events")
    async def events(limit: int = 200):
        return app.state.audit.events(min(limit, 1000))

    @app.post("/api/events/clear")
    async def clear_events():
        app.state.audit.clear()
        return {"ok": True}

    @app.get("/api/stats")
    async def stats():
        return app.state.audit.stats()

    @app.get("/api/stream")
    async def stream(request: Request):
        queue = app.state.audit.subscribe()

        # На бессерверных платформах долгие соединения держать нельзя: поток закрывается,
        # а браузер (EventSource) сам подключается заново.
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
    async def policy():
        p = app.state.engine.policy
        return {"name": p.name, "description": p.description, "default_action": p.default_action,
                "yaml": policy_file.read_text(encoding="utf-8"),
                "tools": [{"name": n, "action": t.action, "description": t.description} for n, t in p.tools.items()]}

    @app.post("/api/check")
    async def check(request: Request):
        body = await request.json()
        d = app.state.engine.evaluate(str(body.get("tool", "")), body.get("args") or {})
        app.state.audit.record(channel="check", tool=d.tool, args=body.get("args") or {}, action=d.action,
                               rule=d.rule, reason=d.reason, owasp=d.owasp, latency_us=d.latency_us,
                               session="manual")
        return d.to_dict()

    @app.get("/api/demo/scenarios")
    async def scenarios():
        return [{k: s.get(k) for k in ("id", "kind", "title", "owasp", "prompt", "note")} for s in runner.SCENARIOS]

    @app.post("/api/demo/run")
    async def demo_run(request: Request):
        body = await request.json()
        sc = runner.scenario(str(body.get("id", "")))
        if sc is None and body.get("prompt"):
            sc = {"id": "custom", "kind": "attack", "title": "Свой запрос", "prompt": str(body["prompt"])}
        if sc is None:
            return JSONResponse({"error": "Сценарий не найден"}, status_code=404)
        return await runner.run_scenario(app, sc, bool(body.get("protected", True)))

    @app.post("/api/redteam/run")
    async def redteam_run():
        return await runner.run_suite(app)

    @app.get("/")
    async def index():
        return FileResponse(DASHBOARD, media_type="text/html")

    return app


async def _as_sse(resp: dict):
    """Отдаёт готовый ответ в виде потока: один фрагмент и маркер конца."""
    chunk = {k: resp.get(k) for k in ("id", "created", "model")}
    chunk["object"] = "chat.completion.chunk"
    chunk["choices"] = []
    for choice in resp.get("choices") or []:
        delta = dict(choice.get("message") or {})
        for i, call in enumerate(delta.get("tool_calls") or []):
            call["index"] = i
        chunk["choices"].append({"index": choice.get("index", 0), "delta": delta,
                                 "finish_reason": choice.get("finish_reason")})
    yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"
