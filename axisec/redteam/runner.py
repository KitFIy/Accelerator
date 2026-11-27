"""Red Team: прогон сценариев атак и обычных задач через агента, с защитой и без."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import httpx
import yaml

from ..demo.agent import run_agent
from ..guards.path import check_path
from ..guards.shell import check_shell
from ..guards.sql import check_sql
from ..policy import PathRules, ShellRules, SqlRules

HERE = Path(__file__).resolve().parent
SCENARIOS: list[dict] = yaml.safe_load((HERE / "scenarios.yaml").read_text(encoding="utf-8"))
CORPUS: list[dict] = yaml.safe_load((HERE / "corpus.yaml").read_text(encoding="utf-8"))
CORPORA_DIR = HERE / "corpora"
_lock = asyncio.Lock()


def evaluate_extra_corpora() -> dict[str, dict]:
    """Прогоняет дополнительные корпуса (PostgreSQL, MySQL, shell, path)."""
    specs = {
        "postgres": (lambda args: check_sql(args["query"], SqlRules(
            dialect="postgres", allow_statements=["select"], tables_allow=["customers", "orders"],
            columns_deny={"customers": ["passport", "card_number"]}, max_rows=50)).ok),
        "mysql": (lambda args: check_sql(args["query"], SqlRules(
            dialect="mysql", allow_statements=["select"], tables_allow=["customers", "orders"],
            columns_deny={"customers": ["passport", "card_number"]}, max_rows=50)).ok),
        "shell": (lambda args: check_shell(args["cmd"], ShellRules(
            allow_commands=["ls", "cat", "grep", "git", "find", "tar"],
            deny_flags={"find": ["-exec", "-execdir", "-delete"], "tar": ["--checkpoint-action"], "git": ["-c", "--upload-pack"]})).ok),
        "path": (lambda args: check_path(args["path"], PathRules(
            allow_roots=["/app/data"], allow_extensions=[".md", ".txt", ".csv", ".json"])).ok),
    }
    report: dict[str, dict] = {}
    for name, is_allowed in specs.items():
        path = CORPORA_DIR / f"{name}.yaml"
        if not path.exists():
            continue
        cases = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        attacks = [c for c in cases if c["expect"] == "block"]
        benign = [c for c in cases if c["expect"] == "allow"]
        report[name] = {
            "attacks": len(attacks),
            "blocked": sum(1 for c in attacks if not is_allowed(c["args"])),
            "benign": len(benign),
            "passed": sum(1 for c in benign if is_allowed(c["args"])),
        }
    return report


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
        "extra_corpora": evaluate_extra_corpora(),
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
