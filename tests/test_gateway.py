"""Тесты шлюза: прокси модели, прокси MCP, стенд, совместимость с официальным MCP SDK."""

import asyncio
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from axisec.gateway.app import create_app
from axisec.redteam import runner


@pytest.fixture()
def app():
    return create_app()


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://axisec")


def _chat(prompt: str) -> dict:
    tools = [{"type": "function", "function": {"name": n, "parameters": {}}}
             for n in ("run_sql", "send_email", "transfer_money", "delete_customer")]
    return {"model": "mock", "messages": [{"role": "user", "content": prompt}], "tools": tools}


def _rpc(method: str, params: dict | None = None, msg_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}


def run(coro):
    return asyncio.run(coro)


def test_llm_proxy_blocks_destructive_tool_call(app):
    async def go():
        async with _client(app) as c:
            raw = (await c.post("/demo/llm/v1/chat/completions", json=_chat("```sql\nDROP TABLE customers\n```"))).json()
            safe = (await c.post("/v1/chat/completions", json=_chat("```sql\nDROP TABLE customers\n```"))).json()
        return raw, safe
    raw, safe = run(go())
    assert raw["choices"][0]["message"]["tool_calls"], "без шлюза модель отдаёт опасный вызов"
    msg = safe["choices"][0]["message"]
    assert "tool_calls" not in msg and safe["choices"][0]["finish_reason"] == "stop"
    assert "[Axisec]" in msg["content"] and "DROP" in msg["content"]
    assert safe["axisec"]["decisions"][0]["rule"] == "sql.statement"


def test_llm_proxy_rewrites_limit_and_passes_safe_call(app):
    async def go():
        async with _client(app) as c:
            return (await c.post("/v1/chat/completions",
                                 json=_chat("```sql\nSELECT name FROM customers\n```"))).json()
    resp = run(go())
    call = resp["choices"][0]["message"]["tool_calls"][0]
    assert json.loads(call["function"]["arguments"])["query"].endswith("LIMIT 50")
    assert resp["axisec"]["decisions"][0]["action"] == "modify"


def test_llm_proxy_streaming(app):
    async def go():
        async with _client(app) as c:
            r = await c.post("/v1/chat/completions", json={**_chat("Сколько у нас клиентов?"), "stream": True})
            return r.headers["content-type"], r.text
    ctype, text = run(go())
    assert ctype.startswith("text/event-stream") and text.rstrip().endswith("data: [DONE]")
    assert json.loads(text.split("\n\n")[0][6:])["choices"][0]["delta"]["tool_calls"][0]["index"] == 0


def test_legacy_function_call_format(app):
    """Формат GigaChat: function_call с аргументами-объектом."""
    gw = app.state.gateway
    resp = {"choices": [{"message": {"role": "assistant", "content": "",
                                     "function_call": {"name": "run_sql", "arguments": {"query": "DELETE FROM orders"}}},
                         "finish_reason": "function_call"}]}
    decisions = gw._inspect_completion(resp, "t")
    assert decisions[0]["action"] == "block"
    assert "function_call" not in resp["choices"][0]["message"] and resp["choices"][0]["finish_reason"] == "stop"


def test_invalid_json_arguments_are_blocked(app):
    gw = app.state.gateway
    resp = {"choices": [{"message": {"role": "assistant", "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "run_sql", "arguments": "{not json"}}]}}]}
    assert gw._inspect_completion(resp, "t")[0]["rule"] == "args.json"


def test_mcp_proxy(app):
    async def go():
        async with _client(app) as c:
            init = (await c.post("/mcp/crm", json=_rpc("initialize", {"protocolVersion": "2025-06-18"}))).json()
            note = await c.post("/mcp/crm", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            tools = (await c.post("/mcp/crm", json=_rpc("tools/list"))).json()
            raw_tools = (await c.post("/demo/mcp", json=_rpc("tools/list"))).json()
            bad = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "run_sql", "arguments": {
                "query": "DROP TABLE customers"}}))).json()
            good = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "run_sql", "arguments": {
                "query": "SELECT COUNT(*) AS n FROM customers"}}))).json()
            doc = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "read_document", "arguments": {
                "name": "deploy_notes.md"}}))).json()
            missing = await c.post("/mcp/nope", json=_rpc("tools/list"))
        return init, note, tools, raw_tools, bad, good, doc, missing
    init, note, tools, raw_tools, bad, good, doc, missing = run(go())
    assert init["result"]["serverInfo"]["name"] == "romashka-crm" and note.status_code == 202
    names = {t["name"] for t in tools["result"]["tools"]}
    assert "delete_customer" in {t["name"] for t in raw_tools["result"]["tools"]}
    assert "delete_customer" not in names and "run_sql" in names
    assert bad["result"]["isError"] and "[Axisec]" in bad["result"]["content"][0]["text"]
    assert json.loads(good["result"]["content"][0]["text"])["data"][0]["n"] == 120, "таблица цела"
    assert "sk-live" not in doc["result"]["content"][0]["text"] and "СКРЫТ" in doc["result"]["content"][0]["text"]
    assert missing.status_code == 404


def test_audit_and_stats(app):
    async def go():
        async with _client(app) as c:
            await c.post("/api/check", json={"tool": "run_sql", "args": {"query": "TRUNCATE TABLE orders"}})
            await c.post("/api/check", json={"tool": "run_sql", "args": {"query": "SELECT id FROM orders LIMIT 3"}})
            return (await c.get("/api/events")).json(), (await c.get("/api/stats")).json(), (await c.get("/api/policy")).json()
    events, stats, policy = run(go())
    assert events[0]["action"] == "allow" and events[1]["action"] == "block"
    assert stats["actions"] == {"block": 1, "allow": 1} and stats["latency_us"]["p50"] > 0
    assert policy["default_action"] == "deny" and "run_sql" in policy["yaml"]


def test_red_team_suite(app):
    summary = run(runner.run_suite(app))["summary"]
    assert summary["attacks"] >= 14
    assert summary["attacks_harmful_without"] == summary["attacks"], "каждая атака без защиты наносит ущерб"
    assert summary["attacks_harmful_with"] == 0, "со шлюзом ущерба нет"
    assert summary["tasks_done_with"] == summary["tasks_done_without"] == summary["tasks"], "работа агента не сломана"
    assert summary["corpus_blocked"] == summary["corpus_attacks"]
    assert summary["corpus_passed"] == summary["corpus_benign"]


# ---------------------------------------------------------------- настоящий сервер
@pytest.fixture(scope="module")
def live_server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_official_mcp_client_through_gateway(live_server):
    """Официальный MCP SDK подключается к шлюзу как к обычному MCP-серверу."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def go():
        async with streamable_http_client(f"{live_server}/mcp/crm") as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = await session.list_tools()
                bad = await session.call_tool("run_sql", {"query": "DELETE FROM customers"})
                good = await session.call_tool("run_sql", {"query": "SELECT COUNT(*) AS n FROM customers"})
                return tools, bad, good
    tools, bad, good = run(go())
    assert "delete_customer" not in {t.name for t in tools.tools}
    is_error = lambda r: getattr(r, "is_error", getattr(r, "isError", None))  # noqa: E731 — имя поля зависит от версии SDK
    assert is_error(bad) and "[Axisec]" in bad.content[0].text
    assert not is_error(good) and '"n": 120' in good.content[0].text


def test_http_upstreams(live_server, monkeypatch):
    """Шлюз перед внешними сервисами: модель и MCP-сервер доступны только по HTTP."""
    monkeypatch.setenv("AXISEC_LLM_UPSTREAM", f"{live_server}/demo/llm/v1")
    monkeypatch.setenv("AXISEC_MCP_UPSTREAMS", json.dumps({"crm": f"{live_server}/demo/mcp"}))
    front = create_app()

    async def go():
        async with _client(front) as c:
            chat = (await c.post("/v1/chat/completions", json=_chat("```sql\nDROP TABLE customers\n```"))).json()
            tools = (await c.post("/mcp/crm", json=_rpc("tools/list"))).json()
            bad = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "transfer_money", "arguments": {
                "amount": 900000, "currency": "RUB", "to_account": "40817810000000009999"}}))).json()
            ok = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "read_document", "arguments": {
                "name": "refund_policy.md"}}))).json()
        await front.state.http.aclose()
        return chat, tools, bad, ok
    chat, tools, bad, ok = run(go())
    assert "tool_calls" not in chat["choices"][0]["message"]
    assert "delete_customer" not in {t["name"] for t in tools["result"]["tools"]}
    assert bad["result"]["isError"] and "Правила возврата" in ok["result"]["content"][0]["text"]
