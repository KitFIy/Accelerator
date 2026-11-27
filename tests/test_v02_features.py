"""Тесты функций v0.2: авторизация, observe, апрувы, RBAC, потоковый SSE, генератор политик, SQLite-аудит и SIEM."""

import asyncio
import json
import os

import httpx
import yaml

from axisec.audit import AuditLog
from axisec.gateway.app import create_app


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://axisec")


def _rpc(method: str, params: dict | None = None, msg_id: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}


def test_admin_and_gateway_auth_and_token_role_binding(tmp_path, monkeypatch):
    pol_path = tmp_path / "rbac.yaml"
    pol_path.write_text(yaml.safe_dump({
        "version": 1,
        "name": "rbac-test",
        "default_action": "deny",
        "tools": {
            "run_sql": {"args": {"query": {"type": "sql", "required": True, "sql": {"allow_statements": ["select", "update"], "tables_allow": ["customers"]}}}},
            "transfer_money": {"args": {"amount": {"type": "number", "required": True, "min": 1, "max": 50000}}},
        },
        "roles": {
            "junior": {"deny_tools": ["transfer_money"], "tools": {"run_sql": {"args": {"query": {"type": "sql", "required": True, "sql": {"allow_statements": ["select"], "tables_allow": ["customers"]}}}}}},
            "senior": {"description": "Старший оператор"},
        },
    }, allow_unicode=True), encoding="utf-8")

    monkeypatch.setenv("AXISEC_ADMIN_TOKEN", "adm-secret")
    monkeypatch.setenv("AXISEC_GATEWAY_TOKENS", json.dumps({"gw-junior": "junior", "gw-senior": "senior"}))
    app = create_app(str(pol_path))

    async def go():
        async with _client(app) as c:
            h = await c.get("/api/health")
            unauth_api = await c.get("/api/events")
            auth_api = await c.get("/api/events", headers={"authorization": "Bearer adm-secret"})
            unauth_mcp = await c.post("/mcp/crm", json=_rpc("tools/list"))
            # Попытка подменить роль через X-Axisec-Role при токене junior не должна сработать
            jun_upd = await c.post("/mcp/crm", headers={"authorization": "Bearer gw-junior", "x-axisec-role": "senior"},
                                   json=_rpc("tools/call", {"name": "run_sql", "arguments": {"query": "UPDATE customers SET city = 'Казань' WHERE id = 1"}}))
            sen_upd = await c.post("/mcp/crm", headers={"authorization": "Bearer gw-senior"},
                                   json=_rpc("tools/call", {"name": "run_sql", "arguments": {"query": "UPDATE customers SET city = 'Казань' WHERE id = 1"}}))
            jun_tools = await c.post("/mcp/crm", headers={"x-axisec-key": "gw-junior"}, json=_rpc("tools/list"))
        await app.state.http.aclose()
        return h, unauth_api, auth_api, unauth_mcp, jun_upd, sen_upd, jun_tools

    h, unauth_api, auth_api, unauth_mcp, jun_upd, sen_upd, jun_tools = asyncio.run(go())
    assert h.status_code == 200 and h.json()["auth_required"] is True and h.json()["gateway_auth_required"] is True
    assert unauth_api.status_code == 401 and auth_api.status_code == 200
    assert unauth_mcp.status_code == 401
    assert jun_upd.json()["result"]["isError"] is True
    assert not sen_upd.json()["result"].get("isError")
    assert "transfer_money" not in {t["name"] for t in jun_tools.json()["result"]["tools"]}


def test_unknown_rbac_role_fails_closed(tmp_path):
    pol_path = tmp_path / "rbac.yaml"
    pol_path.write_text(yaml.safe_dump({
        "tools": {"run_sql": {"args": {"query": {"type": "sql", "required": True, "sql": {"allow_statements": ["select"]}}}}},
        "roles": {"analyst": {"description": "Аналитик"}},
    }), encoding="utf-8")
    app = create_app(str(pol_path))
    d = app.state.engine.evaluate("run_sql", {"query": "SELECT 1"}, role="hacker")
    assert d.blocked and d.rule == "rbac.unknown_role"


def test_observe_mode_logs_would_block_without_blocking(monkeypatch):
    monkeypatch.setenv("AXISEC_MODE", "observe")
    app = create_app()

    async def go():
        async with _client(app) as c:
            tools = (await c.post("/mcp/crm", json=_rpc("tools/list"))).json()
            drop_call = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "run_sql", "arguments": {"query": "DROP TABLE orders"}}))).json()
            doc_call = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "read_document", "arguments": {"name": "deploy_notes.md"}}))).json()
            events = (await c.get("/api/events?action=would_block")).json()
            # Переключение в enforce в рантайме
            await c.post("/api/policy/mode", json={"mode": "enforce"})
            blocked_now = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "run_sql", "arguments": {"query": "DROP TABLE customers"}}))).json()
        await app.state.http.aclose()
        return tools, drop_call, doc_call, events, blocked_now

    tools, drop_call, doc_call, events, blocked_now = asyncio.run(go())
    # В observe не скрываются инструменты и не маскируется текст, но всё фиксируется как would_*
    assert "delete_customer" in {t["name"] for t in tools["result"]["tools"]}
    assert not drop_call["result"].get("isError")
    assert "sk-live-" in doc_call["result"]["content"][0]["text"]
    assert events and events[0]["action"] == "would_block" and events[0]["rule"] == "sql.statement"
    assert blocked_now["result"]["isError"] is True


def test_human_in_the_loop_approve_reject_and_timeout(tmp_path):
    pol_path = tmp_path / "hitl.yaml"
    pol_path.write_text(yaml.safe_dump({
        "tools": {
            "transfer_money": {
                "args": {
                    "amount": {"type": "number", "required": True, "min": 1, "max": 500000, "approve_above": 50000},
                    "currency": {"type": "string", "required": True, "enum": ["RUB"]},
                    "to_account": {"type": "string", "required": True},
                }
            },
            "run_sql": {
                "args": {
                    "query": {"type": "sql", "required": True, "sql": {
                        "allow_statements": ["select"],
                        "approve_statements": ["delete"],
                        "tables_allow": ["orders"],
                        "require_where": ["delete"],
                    }}
                }
            },
        }
    }), encoding="utf-8")
    app = create_app(str(pol_path))

    async def go():
        async with _client(app) as c:
            # 1) Без WHERE DELETE всё равно блокируется жёстко, без постановки в апрув
            no_where = (await c.post("/mcp/crm", json=_rpc("tools/call", {"name": "run_sql", "arguments": {"query": "DELETE FROM orders"}}))).json()

            # 2) Ожидает подтверждения -> оператор подтверждает
            async def approve_soon():
                for _ in range(50):
                    items = (await c.get("/api/approvals?status=pending")).json()
                    if items:
                        await c.post(f"/api/approvals/{items[0]['id']}/approve", json={})
                        return
                    await asyncio.sleep(0.02)

            task = asyncio.create_task(approve_soon())
            approved_call = (await c.post("/mcp/crm", headers={"x-axisec-approval-wait": "2.0"},
                                           json=_rpc("tools/call", {"name": "transfer_money", "arguments": {
                                               "amount": 120000, "currency": "RUB", "to_account": "40702810900000000001"
                                           }}))).json()
            await task

            # 3) Ожидает подтверждения -> оператор отклоняет
            async def reject_soon():
                for _ in range(50):
                    items = (await c.get("/api/approvals?status=pending")).json()
                    if items:
                        await c.post(f"/api/approvals/{items[0]['id']}/reject", json={})
                        return
                    await asyncio.sleep(0.02)

            task2 = asyncio.create_task(reject_soon())
            rejected_call = (await c.post("/mcp/crm", headers={"x-axisec-approval-wait": "2.0"},
                                           json=_rpc("tools/call", {"name": "transfer_money", "arguments": {
                                               "amount": 150000, "currency": "RUB", "to_account": "40702810900000000001"
                                           }}))).json()
            await task2

            # 4) Истечение ожидания -> fail-closed
            timed_out = (await c.post("/mcp/crm", headers={"x-axisec-approval-wait": "0.05"},
                                       json=_rpc("tools/call", {"name": "run_sql", "arguments": {
                                           "query": "DELETE FROM orders WHERE id = 1001"
                                       }}))).json()
        await app.state.http.aclose()
        return no_where, approved_call, rejected_call, timed_out

    no_where, approved_call, rejected_call, timed_out = asyncio.run(go())
    assert no_where["result"]["isError"] is True and "без WHERE" in no_where["result"]["content"][0]["text"]
    assert not approved_call["result"].get("isError") and "120000" in approved_call["result"]["content"][0]["text"]
    assert rejected_call["result"]["isError"] is True and "отклонено оператором" in rejected_call["result"]["content"][0]["text"]
    assert timed_out["result"]["isError"] is True and "ожидает подтверждения" in timed_out["result"]["content"][0]["text"]


def test_real_sse_streaming_blocks_split_tools_and_masks_split_secrets(monkeypatch):
    def sse_bytes(*chunks: dict) -> bytes:
        out = [f"data: {json.dumps(c, ensure_ascii=False)}\n\n" for c in chunks]
        out.append("data: [DONE]\n\n")
        return "".join(out).encode("utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        prompt = body["messages"][-1]["content"]
        if "SECRET_STREAM" in prompt:
            raw = sse_bytes(
                {"id": "s1", "model": "gpt-test", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Ключ: sk-live-4f9a8b"}, "finish_reason": None}]},
                {"id": "s1", "model": "gpt-test", "choices": [{"index": 0, "delta": {"content": "7c6d5e4f3a2b1c0d9e8f7a6b5c!"}, "finish_reason": "stop"}]},
            )
        elif "DROP_STREAM" in prompt:
            raw = sse_bytes(
                {"id": "s2", "model": "gpt-test", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "run_sql", "arguments": "{\"query\": \"DROP "}}]}, "finish_reason": None}]},
                {"id": "s2", "model": "gpt-test", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "TABLE customers\"}"}}]}, "finish_reason": "tool_calls"}]},
            )
        else:
            raw = sse_bytes(
                {"id": "s3", "model": "gpt-test", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c2", "type": "function", "function": {"name": "run_sql", "arguments": "{\"query\": \"SELECT name FROM customers\"}"}}]}, "finish_reason": "tool_calls"}]},
            )
        return httpx.Response(200, content=raw, headers={"content-type": "text/event-stream"})

    monkeypatch.setenv("AXISEC_LLM_UPSTREAM", "https://llm.mock/v1")
    app = create_app()
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.gateway.http = app.state.http

    async def go():
        async with _client(app) as c:
            r1 = await c.post("/v1/chat/completions", json={"model": "m", "stream": True, "messages": [{"role": "user", "content": "SECRET_STREAM"}]})
            r2 = await c.post("/v1/chat/completions", json={"model": "m", "stream": True, "messages": [{"role": "user", "content": "DROP_STREAM"}]})
            r3 = await c.post("/v1/chat/completions", json={"model": "m", "stream": True, "messages": [{"role": "user", "content": "SAFE_STREAM"}]})
        await app.state.http.aclose()
        return r1.text, r2.text, r3.text

    t1, t2, t3 = asyncio.run(go())
    assert "sk-live-" not in t1 and "API_КЛЮЧ_СКРЫТ" in t1
    assert "DROP" in t2 and "[Axisec]" in t2 and '"tool_calls"' not in t2 and '"finish_reason": "stop"' in t2
    assert "LIMIT 50" in t3 and '"tool_calls"' in t3


def test_mcp_get_sse_stream_proxy(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            content=b'data: {"jsonrpc":"2.0","method":"notifications/ping"}\n\n',
            headers={"content-type": "text/event-stream", "mcp-session-id": "sess-1"},
        )

    monkeypatch.setenv("AXISEC_MCP_UPSTREAMS", json.dumps({"ext": "https://mcp.mock/mcp"}))
    app = create_app()
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.gateway.http = app.state.http

    async def go():
        async with _client(app) as c:
            r = await c.get("/mcp/ext", headers={"accept": "text/event-stream"})
        await app.state.http.aclose()
        return r

    res = asyncio.run(go())
    assert res.status_code == 200
    assert res.headers.get("mcp-session-id") == "sess-1"
    assert "notifications/ping" in res.text


def test_policy_draft_reload_sqlite_persistence_and_siem_export(tmp_path):
    db_file = tmp_path / "audit.sqlite"
    app = create_app(audit_db=str(db_file))

    async def go():
        async with _client(app) as c:
            await c.post("/api/check", json={"tool": "run_sql", "args": {"query": "DROP TABLE orders"}})
            await c.post("/api/check", json={"tool": "run_sql", "args": {"query": "SELECT id FROM orders LIMIT 5"}})
            draft = (await c.post("/api/policy/draft", json={"server": "crm", "use_audit": True})).json()
            bad_reload = await c.post("/api/policy/reload", json={"yaml": "tools:\n  x: {action: invalid_action}"})
            ok_reload = await c.post("/api/policy/reload", json={"yaml": draft["yaml"]})
            cef = (await c.get("/api/events/export?format=cef")).text
            jsonl = (await c.get("/api/events/export?format=jsonl")).text
            prom = (await c.get("/metrics")).text
        await app.state.http.aclose()
        return draft, bad_reload, ok_reload, cef, jsonl, prom

    draft, bad_reload, ok_reload, cef, jsonl, prom = asyncio.run(go())
    assert draft["tools_count"] == 6 and draft["policy"]["tools"]["delete_customer"]["action"] == "deny"
    assert draft["policy"]["tools"]["run_sql"]["args"]["query"]["type"] == "sql"
    assert bad_reload.status_code == 400
    assert ok_reload.status_code == 200 and ok_reload.json()["mode"] == "observe"
    assert "CEF:0|Axisec|Gateway|" in cef
    assert len(jsonl.strip().splitlines()) == 2
    assert "axisec_decisions_total" in prom and "axisec_blocked_rules_total" in prom

    # Переоткрытие AuditLog должно загрузить сохранённые события из SQLite и восстановить счётчик id
    reopened = AuditLog(db_file)
    assert len(reopened.events(10)) == 2
    ev3 = reopened.record(channel="check", tool="run_sql", args={}, action="allow")
    assert ev3["id"] == 3
    reopened.clear()
    assert AuditLog(db_file).events(10) == []


def test_dotenv_loader_and_invalid_json_400(tmp_path, monkeypatch):
    from axisec.env import load_dotenv

    env_file = tmp_path / ".env"
    env_file.write_text("# comment\nAXISEC_TEST_FOO='bar_baz'\nAXISEC_TEST_EXISTING=from_file\n", encoding="utf-8")
    monkeypatch.delenv("AXISEC_TEST_FOO", raising=False)
    monkeypatch.setenv("AXISEC_TEST_EXISTING", "from_os")
    load_dotenv(env_file)
    assert os.environ["AXISEC_TEST_FOO"] == "bar_baz"
    assert os.environ["AXISEC_TEST_EXISTING"] == "from_os"

    app = create_app()

    async def go():
        async with _client(app) as c:
            r1 = await c.post("/v1/chat/completions", content=b"{bad", headers={"content-type": "application/json"})
            r2 = await c.post("/api/check", content=b"{bad", headers={"content-type": "application/json"})
        await app.state.http.aclose()
        return r1, r2

    r1, r2 = asyncio.run(go())
    assert r1.status_code == 400 and r2.status_code == 400
