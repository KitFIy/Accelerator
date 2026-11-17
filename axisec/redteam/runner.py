"""Red Team: прогон сценариев атак и обычных задач через агента, с защитой и без."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import httpx
import yaml

from ..demo.agent import run_agent

HERE = Path(__file__).resolve().parent
SCENARIOS: list[dict] = yaml.safe_load((HERE / "scenarios.yaml").read_text(encoding="utf-8"))
CORPUS: list[dict] = yaml.safe_load((HERE / "corpus.yaml").read_text(encoding="utf-8"))
_lock = asyncio.Lock()


def scenario(scenario_id: str) -> dict | None:
    return next((s for s in SCENARIOS if s["id"] == scenario_id), None)


async def run_scenario(app, sc: dict, protected: bool) -> dict:
    """Сбрасывает демо-мир, запускает агента и возвращает шаги, решения шлюза и фактический ущерб."""
    world, audit = app.state.world, app.state.audit
    session = f"{sc['id']}-{'on' if protected else 'off'}-{uuid.uuid4().hex[:6]}"
    async with _lock:
        world.reset()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://axisec") as client:
            result = await run_agent(client, "/v1" if protected else "/demo/llm/v1",
                                     "/mcp/crm" if protected else "/demo/mcp", sc["prompt"], session=session)
        harms = world.harms(result["saw"])
        done = any(c["tool"] == sc.get("done") and c["ok"] for c in world.calls) if sc.get("done") else None
    decisions = [e for e in audit.events(500) if e["session"] == session][::-1]
    return {"id": sc["id"], "title": sc["title"], "kind": sc["kind"], "owasp": sc.get("owasp", []),
            "prompt": sc["prompt"], "note": sc.get("note", ""), "protected": protected,
            "steps": result["steps"], "harms": harms, "done": done, "decisions": decisions}


async def run_suite(app) -> dict:
    """Полный прогон: каждый сценарий без защиты и с защитой, плюс корпус прямых вызовов."""
    started = time.time()
    rows = []
    for sc in SCENARIOS:
        off = await run_scenario(app, sc, protected=False)
        on = await run_scenario(app, sc, protected=True)
        rows.append({"id": sc["id"], "title": sc["title"], "kind": sc["kind"], "owasp": sc.get("owasp", []),
                     "harms_off": off["harms"], "harms_on": on["harms"], "done_off": off["done"],
                     "done_on": on["done"],
                     "rules": sorted({d["rule"] for d in on["decisions"]
                                      if d["action"] in ("block", "mask", "hide")})})
    attacks = [r for r in rows if r["kind"] == "attack"]
    tasks = [r for r in rows if r["kind"] == "task"]
    engine = app.state.engine
    blocked = sum(1 for c in CORPUS if c["expect"] == "block" and engine.evaluate(c["tool"], c["args"]).blocked)
    passed = sum(1 for c in CORPUS if c["expect"] == "allow" and not engine.evaluate(c["tool"], c["args"]).blocked)
    return {
        "rows": rows,
        "summary": {
            "attacks": len(attacks),
            "attacks_harmful_without": sum(1 for r in attacks if r["harms_off"]),
            "attacks_harmful_with": sum(1 for r in attacks if r["harms_on"]),
            "tasks": len(tasks),
            "tasks_done_without": sum(1 for r in tasks if r["done_off"]),
            "tasks_done_with": sum(1 for r in tasks if r["done_on"] and not r["harms_on"]),
            "corpus_attacks": sum(1 for c in CORPUS if c["expect"] == "block"), "corpus_blocked": blocked,
            "corpus_benign": sum(1 for c in CORPUS if c["expect"] == "allow"), "corpus_passed": passed,
            "seconds": round(time.time() - started, 2),
        },
    }
