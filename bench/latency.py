"""Замеры задержки шлюза. Запуск: python bench/latency.py

1. Движок: время одной проверки вызова на корпусе.
2. Сквозной путь по HTTP: тот же запрос к MCP-серверу напрямую и через шлюз,
   разница и есть накладные расходы шлюза.
"""

from __future__ import annotations

import json
import platform
import socket
import statistics
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from axisec.engine import PolicyEngine  # noqa: E402
from axisec.gateway.app import create_app  # noqa: E402
from axisec.policy import load_policy  # noqa: E402


def pct(values: list[float], p: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


def summary(values: list[float], digits: int = 1) -> dict:
    return {"n": len(values), "p50": round(statistics.median(values), digits),
            "p95": round(pct(values, 0.95), digits), "p99": round(pct(values, 0.99), digits),
            "max": round(max(values), digits)}


def bench_engine(rounds: int = 200) -> dict:
    engine = PolicyEngine(load_policy(ROOT / "policies/crm_agent.yaml"))
    corpus = yaml.safe_load((ROOT / "axisec/redteam/corpus.yaml").read_text(encoding="utf-8"))
    for c in corpus:  # прогрев
        engine.evaluate(c["tool"], c["args"])
    all_us, sql_us, api_us = [], [], []
    started = time.perf_counter()
    for _ in range(rounds):
        for c in corpus:
            us = engine.evaluate(c["tool"], c["args"]).latency_us
            all_us.append(us)
            (sql_us if c["tool"] == "run_sql" else api_us).append(us)
    elapsed = time.perf_counter() - started
    return {"all_us": summary(all_us), "sql_us": summary(sql_us), "api_us": summary(api_us),
            "checks_per_second_one_core": round(len(all_us) / elapsed)}


def bench_http(requests: int = 1500) -> dict:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "run_sql", "arguments": {"query": "SELECT id, status FROM orders WHERE id = 1001"}}}
    result = {}
    with httpx.Client() as client:
        for name, url in (("direct_ms", f"{base}/demo/mcp"), ("through_gateway_ms", f"{base}/mcp/crm")):
            for _ in range(100):
                client.post(url, json=call)
            times = []
            for _ in range(requests):
                t0 = time.perf_counter()
                client.post(url, json=call)
                times.append((time.perf_counter() - t0) * 1000)
            result[name] = summary(times, 3)
    server.should_exit = True
    thread.join(timeout=5)
    result["overhead_ms_p50"] = round(result["through_gateway_ms"]["p50"] - result["direct_ms"]["p50"], 3)
    return result


if __name__ == "__main__":
    report = {"python": platform.python_version(), "machine": platform.machine(), "cpu_count": __import__("os").cpu_count(),
              "engine": bench_engine(), "http": bench_http()}
    out = ROOT / "bench" / "results.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
