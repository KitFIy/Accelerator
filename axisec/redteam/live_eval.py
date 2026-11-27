"""Оценка сценариев Red Team на реальной модели (GigaChat, YandexGPT или OpenAI-совместимой).

Запуск:
  python -m axisec.redteam.live_eval --provider gigachat --model GigaChat-2-Pro
  python -m axisec.redteam.live_eval --provider yandex --model yandexgpt --output bench/live_yandex.json

Учётные данные берутся из переменных окружения:
  AXISEC_LLM_UPSTREAM, AXISEC_LLM_API_KEY,
  AXISEC_GIGACHAT_AUTH_KEY, AXISEC_GIGACHAT_SCOPE,
  AXISEC_YANDEX_FOLDER_ID, AXISEC_LLM_VERIFY_TLS, AXISEC_LLM_CA_BUNDLE.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..audit import AuditLog
from ..demo import mcp_server
from ..demo.agent import run_agent
from ..demo.world import World
from ..engine import PolicyEngine
from ..gateway.app import create_app
from ..gateway.providers import ProviderAdapter
from ..gateway.proxy import Gateway
from ..policy import DlpPolicy, Policy
from .runner import SCENARIOS


def _make_unprotected_gateway(provider: ProviderAdapter, http: httpx.AsyncClient) -> tuple[World, Gateway]:
    """Шлюз без ограничений: только переводит протокол провайдера, не блокируя и не скрывая вызовы."""
    policy = Policy(name="unprotected", default_action="allow", dlp=DlpPolicy(responses="off", requests="off"))
    world = World()
    audit = AuditLog()
    gw = Gateway(PolicyEngine(policy), audit, world, http, provider_adapter=provider)
    return world, gw


async def evaluate_live(
    *,
    provider: str = "",
    upstream: str = "",
    model: str = "mock-obedient-1",
    scenario_ids: list[str] | None = None,
    protected_app=None,
    http_client: httpx.AsyncClient | None = None,
) -> dict:
    app = protected_app or create_app()
    gw_protected: Gateway = app.state.gateway
    adapter = gw_protected.provider
    if provider or upstream:
        adapter = ProviderAdapter(
            upstream or os.getenv("AXISEC_LLM_UPSTREAM", "demo"),
            provider=provider or os.getenv("AXISEC_LLM_PROVIDER", ""),
            api_key=os.getenv("AXISEC_LLM_API_KEY", ""),
        )
        gw_protected.provider = adapter

    own_http = http_client is None
    client_http = http_client or app.state.http
    selected = [s for s in SCENARIOS if not scenario_ids or s["id"] in scenario_ids]

    # Для режима без защиты поднимаем минимальный ASGI-сервис с тем же адаптером провайдера
    raw_world, raw_gw = _make_unprotected_gateway(adapter, client_http)
    raw_gw.http = client_http
    gw_protected.http = client_http

    raw_app = FastAPI()

    @raw_app.post("/v1/chat/completions")
    async def raw_chat(req: Request):
        status, resp = await raw_gw.chat(await req.json(), req.headers.get("x-axisec-session", ""))
        return JSONResponse(resp, status_code=status)

    @raw_app.post("/demo/mcp")
    async def raw_mcp(req: Request):
        resp = mcp_server.handle(raw_world, await req.json())
        return JSONResponse(resp or {})

    started = time.time()
    rows = []
    try:
        for sc in selected:
            # Без защиты
            raw_world.reset()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=raw_app), base_url="http://raw") as c:
                off = await run_agent(c, "/v1", "/demo/mcp", sc["prompt"],
                                      session=f"live-off-{sc['id']}-{uuid.uuid4().hex[:6]}", model=model)
            harms_off = raw_world.harms(off["saw"])
            done_off = any(call["tool"] == sc.get("done") and call["ok"] for call in raw_world.calls) if sc.get("done") else None

            # Через Axisec
            app.state.world.reset()
            sess = f"live-on-{sc['id']}-{uuid.uuid4().hex[:6]}"
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://axisec") as c:
                on = await run_agent(c, "/v1", "/mcp/crm", sc["prompt"], session=sess, model=model)
            harms_on = app.state.world.harms(on["saw"])
            done_on = any(call["tool"] == sc.get("done") and call["ok"] for call in app.state.world.calls) if sc.get("done") else None
            decisions = [e for e in app.state.audit.events(500) if e["session"] == sess]

            rows.append({
                "id": sc["id"],
                "title": sc["title"],
                "kind": sc["kind"],
                "owasp": sc.get("owasp", []),
                "harms_off": harms_off,
                "harms_on": harms_on,
                "done_off": done_off,
                "done_on": done_on,
                "rules": sorted({d["rule"] for d in decisions if d["action"] in ("block", "mask", "hide")}),
            })
    finally:
        if own_http and not app.state.http.is_closed:
            await app.state.http.aclose()

    attacks = [r for r in rows if r["kind"] == "attack"]
    tasks = [r for r in rows if r["kind"] == "task"]
    return {
        "provider": adapter.provider,
        "model": model,
        "upstream": adapter.upstream,
        "rows": rows,
        "summary": {
            "attacks": len(attacks),
            "attacks_harmful_without": sum(1 for r in attacks if r["harms_off"]),
            "attacks_harmful_with": sum(1 for r in attacks if r["harms_on"]),
            "tasks": len(tasks),
            "tasks_done_without": sum(1 for r in tasks if r["done_off"]),
            "tasks_done_with": sum(1 for r in tasks if r["done_on"] and not r["harms_on"]),
            "seconds": round(time.time() - started, 2),
        },
    }


def format_markdown(report: dict) -> str:
    lines = [
        f"### Модель `{report['model']}` (`{report['provider']}`)",
        "",
        "| Сценарий | Тип | Ущерб без шлюза | Через Axisec | Сработало |",
        "|---|---|---|---|---|",
    ]
    for r in report["rows"]:
        if r["kind"] == "attack":
            off = "; ".join(r["harms_off"]) if r["harms_off"] else "модель отказалась сама"
            on = "; ".join(r["harms_on"]) if r["harms_on"] else "ущерба нет"
        else:
            off = "выполнено" if r["done_off"] else "не выполнено"
            on = "выполнено" if (r["done_on"] and not r["harms_on"]) else "не выполнено"
        rules = ", ".join(f"`{x}`" for x in r["rules"]) or "—"
        lines.append(f"| {r['id']} {r['title']} | {r['kind']} | {off} | {on} | {rules} |")
    s = report["summary"]
    lines.append("")
    lines.append(
        f"Итого: атак с ущербом без шлюза — **{s['attacks_harmful_without']}/{s['attacks']}**, "
        f"через Axisec — **{s['attacks_harmful_with']}/{s['attacks']}**; "
        f"обычных задач выполнено — **{s['tasks_done_with']}/{s['tasks']}**."
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Прогон сценариев Red Team на реальной LLM через Axisec")
    parser.add_argument("--provider", default="", help="auto | openai | gigachat | yandex | demo")
    parser.add_argument("--upstream", default="", help="URL OpenAI-совместимого API или GigaChat/Yandex")
    parser.add_argument("--model", default=os.getenv("AXISEC_LLM_MODEL", "mock-obedient-1"))
    parser.add_argument("--ids", default="", help="Список ID сценариев через запятую (по умолчанию все)")
    parser.add_argument("--output", default="", help="Путь для сохранения JSON-отчёта")
    args = parser.parse_args()

    ids = [x.strip() for x in args.ids.split(",") if x.strip()] or None
    report = asyncio.run(evaluate_live(provider=args.provider, upstream=args.upstream, model=args.model, scenario_ids=ids))
    if args.output:
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(format_markdown(report))


if __name__ == "__main__":
    main()
