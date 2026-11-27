"""Нагрузочный замер шлюза с параллельными клиентами (50, 100, 200).

Запуск: .venv\\Scripts\\python.exe bench/load.py
Результат: bench/load_results.json

Поднимает отдельный процесс сервера (`python -m axisec`) и запускает пул из 50/100/200
параллельных клиентов с постоянными HTTP-соединениями, сравнивая прямой демо-MCP
(`/demo/mcp`) и прохождение через шлюз (`/mcp/crm`).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]

MCP_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "run_sql", "arguments": {"query": "SELECT id, status FROM orders WHERE id = 1001"}},
}


def _pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def _summarize(latencies_ms: list[float], total_s: float, errors: int, sample_error: str = "") -> dict:
    ok = len(latencies_ms)
    out: dict = {
        "ok": ok,
        "errors": errors,
        "rps": round(ok / total_s, 1) if total_s > 0 else 0.0,
        "p50_ms": round(statistics.median(latencies_ms), 3) if ok else 0.0,
        "p95_ms": round(_pct(latencies_ms, 0.95), 3) if ok else 0.0,
        "p99_ms": round(_pct(latencies_ms, 0.99), 3) if ok else 0.0,
        "max_ms": round(max(latencies_ms), 3) if ok else 0.0,
    }
    if sample_error:
        out["sample_error"] = sample_error
    return out


def _run_level(base: str, path: str, concurrency: int, total_requests: int) -> dict:
    clients = [httpx.Client(base_url=base, timeout=30.0) for _ in range(concurrency)]
    per_worker = max(1, total_requests // concurrency)
    errors = 0
    sample_error = ""
    latencies: list[float] = []

    try:
        # Прогрев постоянных соединений
        for c in clients:
            c.post(path, json=MCP_CALL)

        def worker(client: httpx.Client) -> tuple[list[float], int, str]:
            local_lats: list[float] = []
            local_errs = 0
            err_msg = ""
            for _ in range(per_worker):
                t0 = time.perf_counter()
                try:
                    r = client.post(path, json=MCP_CALL)
                    if r.status_code != 200:
                        local_errs += 1
                        if not err_msg:
                            err_msg = f"HTTP {r.status_code}"
                    else:
                        local_lats.append((time.perf_counter() - t0) * 1000)
                except httpx.HTTPError as exc:
                    local_errs += 1
                    if not err_msg:
                        err_msg = str(exc)
            return local_lats, local_errs, err_msg

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            for w_lats, w_errs, w_msg in pool.map(worker, clients):
                latencies.extend(w_lats)
                errors += w_errs
                if w_msg and not sample_error:
                    sample_error = w_msg
        elapsed = time.perf_counter() - started
    finally:
        for c in clients:
            c.close()

    return _summarize(latencies, elapsed, errors, sample_error)


def run_load_bench(levels: tuple[int, ...] = (50, 100, 200)) -> dict:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    proc = subprocess.Popen(
        [sys.executable, "-m", "axisec", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    ready = False
    for _ in range(100):
        try:
            if httpx.get(f"{base}/api/health", timeout=1.0).status_code == 200:
                ready = True
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    if not ready:
        proc.terminate()
        raise RuntimeError("Не удалось дождаться старта сервера Axisec для нагрузочного замера")

    results: list[dict] = []
    try:
        for conc in levels:
            reqs = max(1000, conc * 10)
            direct = _run_level(base, "/demo/mcp", conc, reqs)
            gateway = _run_level(base, "/mcp/crm", conc, reqs)
            results.append({
                "concurrency": conc,
                "requests": direct["ok"] + direct["errors"],
                "direct": direct,
                "through_gateway": gateway,
                "overhead_p50_ms": round(gateway["p50_ms"] - direct["p50_ms"], 3),
            })
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    return {
        "python": platform.python_version(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "workers": 1,
        "levels": results,
    }


if __name__ == "__main__":
    report = run_load_bench()
    out = ROOT / "bench" / "load_results.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
