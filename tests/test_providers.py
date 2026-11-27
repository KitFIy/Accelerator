"""Тесты адаптеров GigaChat, YandexGPT и CLI-оценки сценариев."""

import asyncio
import json

import httpx

from axisec.gateway.app import create_app
from axisec.gateway.providers import (
    ProviderAdapter,
    detect_provider,
    openai_to_gigachat_request,
)
from axisec.redteam.live_eval import evaluate_live, format_markdown


def test_detect_provider():
    assert detect_provider("demo") == "demo"
    assert detect_provider("https://api.giga.chat/v1") == "gigachat"
    assert detect_provider("https://gigachat.devices.sberbank.ru/api/v1") == "gigachat"
    assert detect_provider("https://llm.api.cloud.yandex.net/v1") == "yandex"
    assert detect_provider("https://api.openai.com/v1") == "openai"
    assert detect_provider("https://custom.local/v1", explicit="gigachat") == "gigachat"


def test_openai_to_gigachat_translation():
    req = {
        "model": "GigaChat-2-Pro",
        "tools": [{"type": "function", "function": {"name": "run_sql", "parameters": {"type": "object"}}}],
        "messages": [
            {"role": "user", "content": "Покажи заказы"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "run_sql", "arguments": '{"query": "SELECT 1"}'}}
            ]},
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
        ],
    }
    gc, converted = openai_to_gigachat_request(req)
    assert converted is True
    assert "tools" not in gc and gc["functions"][0]["name"] == "run_sql" and gc["function_call"] == "auto"
    assert gc["messages"][1]["function_call"] == {"name": "run_sql", "arguments": {"query": "SELECT 1"}}
    assert gc["messages"][2]["role"] == "function" and gc["messages"][2]["name"] == "run_sql"
    assert json.loads(gc["messages"][2]["content"]) == {"result": "ok"}


def test_gigachat_oauth_functions_blocking_and_allow(monkeypatch):
    seen = {"oauth_calls": 0, "chat_bodies": [], "auth_headers": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://oauth.mock/api/v2/oauth":
            seen["oauth_calls"] += 1
            assert request.headers["authorization"] == "Basic c2VjcmV0"
            assert request.headers["rquid"]
            return httpx.Response(200, json={"access_token": f"gc-tok-{seen['oauth_calls']}", "expires_in": 1800})
        if str(request.url) == "https://api.giga.chat/v1/chat/completions":
            seen["auth_headers"].append(request.headers["authorization"])
            body = json.loads(request.content.decode())
            seen["chat_bodies"].append(body)
            user_text = body["messages"][-1]["content"]
            if "DROP" in user_text:
                return httpx.Response(200, json={
                    "id": "gc-1", "created": 1, "model": "GigaChat-2-Pro",
                    "choices": [{"index": 0, "finish_reason": "function_call", "message": {
                        "role": "assistant", "content": "",
                        "function_call": {"name": "run_sql", "arguments": {"query": "DROP TABLE customers"}},
                    }}],
                })
            return httpx.Response(200, json={
                "id": "gc-2", "created": 1, "model": "GigaChat-2-Pro",
                "choices": [{"index": 0, "finish_reason": "function_call", "message": {
                    "role": "assistant", "content": "",
                    "function_call": {"name": "run_sql", "arguments": {"query": "SELECT name FROM customers"}},
                }}],
            })
        return httpx.Response(404)

    monkeypatch.setenv("AXISEC_LLM_PROVIDER", "gigachat")
    monkeypatch.setenv("AXISEC_LLM_UPSTREAM", "https://api.giga.chat/v1")
    monkeypatch.setenv("AXISEC_GIGACHAT_OAUTH_URL", "https://oauth.mock/api/v2/oauth")
    monkeypatch.setenv("AXISEC_GIGACHAT_AUTH_KEY", "c2VjcmV0")

    app = create_app()
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.gateway.http = app.state.http

    tools = [{"type": "function", "function": {"name": "run_sql", "parameters": {}}}]

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://axisec") as c:
            blocked = (await c.post("/v1/chat/completions", json={
                "model": "GigaChat-2-Pro", "messages": [{"role": "user", "content": "DROP"}], "tools": tools,
            })).json()
            allowed = (await c.post("/v1/chat/completions", json={
                "model": "GigaChat-2-Pro", "messages": [{"role": "user", "content": "SELECT"}], "tools": tools,
            })).json()
        await app.state.http.aclose()
        return blocked, allowed

    blocked, allowed = asyncio.run(go())
    # Токен OAuth получен ровно 1 раз и закэширован
    assert seen["oauth_calls"] == 1
    assert seen["auth_headers"] == ["Bearer gc-tok-1", "Bearer gc-tok-1"]
    # Запрос к GigaChat ушёл с массивом functions
    assert "functions" in seen["chat_bodies"][0] and "tools" not in seen["chat_bodies"][0]
    # Опасный вызов заблокирован до выхода клиенту
    msg_b = blocked["choices"][0]["message"]
    assert "tool_calls" not in msg_b and "function_call" not in msg_b
    assert "[Axisec]" in msg_b["content"] and blocked["axisec"]["decisions"][0]["rule"] == "sql.statement"
    # Разрешённый вызов нормализован обратно в tool_calls с добавленным LIMIT 50
    tc = allowed["choices"][0]["message"]["tool_calls"][0]
    assert tc["function"]["name"] == "run_sql"
    assert json.loads(tc["function"]["arguments"])["query"].endswith("LIMIT 50")


def test_yandex_headers_and_api_key(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["folder"] = request.headers.get("x-folder-id")
        return httpx.Response(200, json={
            "id": "ya-1", "created": 1, "model": "yandexgpt",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "c1", "type": "function", "function": {
                    "name": "transfer_money",
                    "arguments": json.dumps({"amount": 900000, "currency": "RUB", "to_account": "40817810000000009999"}),
                }}],
            }}],
        })

    monkeypatch.setenv("AXISEC_LLM_PROVIDER", "yandex")
    monkeypatch.setenv("AXISEC_LLM_UPSTREAM", "https://llm.api.cloud.yandex.net/v1")
    monkeypatch.setenv("AXISEC_LLM_API_KEY", "AQVN_test_key")
    monkeypatch.setenv("AXISEC_YANDEX_FOLDER_ID", "b1g-folder-123")

    app = create_app()
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.gateway.http = app.state.http

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://axisec") as c:
            res = (await c.post("/v1/chat/completions", json={
                "model": "yandexgpt", "messages": [{"role": "user", "content": "переведи"}], "tools": [],
            })).json()
        await app.state.http.aclose()
        return res

    res = asyncio.run(go())
    assert captured["url"] == "https://llm.api.cloud.yandex.net/v1/chat/completions"
    assert captured["auth"] == "Api-Key AQVN_test_key"
    assert captured["folder"] == "b1g-folder-123"
    assert res["axisec"]["decisions"][0]["rule"] == "args.amount.max"


def test_gigachat_oauth_refreshes_on_401():
    calls = {"oauth": 0, "chat": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "oauth" in str(request.url):
            calls["oauth"] += 1
            return httpx.Response(200, json={"access_token": f"tok-{calls['oauth']}", "expires_in": 1800})
        calls["chat"] += 1
        if calls["chat"] == 1:
            return httpx.Response(401, json={"message": "expired"})
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]})

    adapter = ProviderAdapter("https://api.giga.chat/v1", provider="gigachat",
                              gigachat_auth_key="abc", gigachat_oauth_url="https://oauth.mock/api/v2/oauth")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await adapter.send_chat({"model": "GigaChat", "messages": [{"role": "user", "content": "hi"}]}, "", http)

    status, resp, _ = asyncio.run(go())
    assert status == 200 and resp["choices"][0]["message"]["content"] == "ok"
    assert calls == {"oauth": 2, "chat": 2}


def test_live_eval_with_mocked_gigachat_subset(monkeypatch):
    from axisec.demo import mock_llm

    def handler(request: httpx.Request) -> httpx.Response:
        if "oauth" in str(request.url):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 1800})
        body = json.loads(request.content.decode())
        # Переводим обратно в OpenAI-вид для имитации послушной модели в GigaChat-формате
        tools = [{"type": "function", "function": f} for f in body.get("functions", [])]
        msgs = []
        for m in body.get("messages", []):
            if m.get("role") == "function":
                msgs.append({"role": "tool", "content": m.get("content", "")})
            elif m.get("role") == "assistant" and m.get("function_call"):
                msgs.append({"role": "assistant", "tool_calls": [{"id": "1", "function": m["function_call"]}]})
            else:
                msgs.append(m)
        oa = mock_llm.complete({"model": body.get("model"), "messages": msgs, "tools": tools})
        msg = oa["choices"][0]["message"]
        if msg.get("tool_calls"):
            tc = msg["tool_calls"][0]["function"]
            gc_msg = {"role": "assistant", "content": "", "function_call": {
                "name": tc["name"], "arguments": json.loads(tc["arguments"]),
            }}
            oa["choices"][0]["message"] = gc_msg
            oa["choices"][0]["finish_reason"] = "function_call"
        return httpx.Response(200, json=oa)

    monkeypatch.setenv("AXISEC_LLM_PROVIDER", "gigachat")
    monkeypatch.setenv("AXISEC_LLM_UPSTREAM", "https://api.giga.chat/v1")
    monkeypatch.setenv("AXISEC_GIGACHAT_OAUTH_URL", "https://oauth.mock/api/v2/oauth")
    monkeypatch.setenv("AXISEC_GIGACHAT_AUTH_KEY", "abc")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await evaluate_live(model="GigaChat-2-Pro", scenario_ids=["A01", "A04", "U01"], http_client=http)

    report = asyncio.run(go())
    assert report["provider"] == "gigachat"
    assert report["summary"]["attacks_harmful_without"] == 2
    assert report["summary"]["attacks_harmful_with"] == 0
    assert report["summary"]["tasks_done_with"] == 1
    md = format_markdown(report)
    assert "GigaChat-2-Pro" in md and "A04" in md
