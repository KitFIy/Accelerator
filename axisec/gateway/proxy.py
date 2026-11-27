"""Две точки контроля шлюза.

1. Ответ модели (OpenAI-совместимый Chat Completions): вызовы инструментов
   проверяются до того, как их увидит и исполнит обвязка агента.
2. MCP (JSON-RPC, метод tools/call): вызов проверяется перед самим ресурсом.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..audit import AuditLog
from ..demo import mcp_server, mock_llm
from ..demo.world import World
from ..engine import Decision, PolicyEngine
from .providers import ProviderAdapter, ProviderError, gigachat_to_openai_response

DEMO = "demo"
_PASS_HEADERS = ("authorization", "mcp-session-id", "mcp-protocol-version", "accept")


def _notice(d: Decision) -> str:
    return f"[Axisec] Действие «{d.tool}» заблокировано: {d.reason} (правило {d.rule})."


class Gateway:
    def __init__(self, engine: PolicyEngine, audit: AuditLog, world: World, http: httpx.AsyncClient,
                 llm_upstream: str = DEMO, llm_api_key: str = "", mcp_upstreams: dict[str, str] | None = None,
                 llm_provider: str = "", provider_adapter: ProviderAdapter | None = None):
        self.engine, self.audit, self.world, self.http = engine, audit, world, http
        self.llm_upstream, self.llm_api_key = llm_upstream, llm_api_key
        self.mcp_upstreams = mcp_upstreams or {"crm": DEMO}
        self.provider = provider_adapter or ProviderAdapter(llm_upstream, provider=llm_provider, api_key=llm_api_key)

    def _log(self, channel: str, d: Decision, args: Any, session: str) -> None:
        self.audit.record(channel=channel, tool=d.tool, args=args, action=d.action, rule=d.rule,
                          reason=d.reason, owasp=d.owasp, latency_us=d.latency_us, session=session)

    # ------------------------------------------------------------------ модель
    async def chat(self, body: dict, session: str = "", authorization: str = "") -> tuple[int, dict]:
        body = dict(body)
        body.pop("stream", None)
        if self.engine.policy.dlp.requests == "mask":
            body["messages"] = [self._mask_message(m, session) for m in body.get("messages", [])]
        normalize_fc = False
        if self.provider.provider == DEMO:
            status, resp = 200, mock_llm.complete(body)
        else:
            try:
                status, resp, normalize_fc = await self.provider.send_chat(body, authorization, self.http)
            except ProviderError as err:
                return err.status_code, {"error": {"message": str(err), "type": "axisec_provider"}}
            except httpx.HTTPError as err:
                return 502, {"error": {"message": f"Ошибка сети при обращении к модели: {err}", "type": "axisec_upstream"}}
            if status >= 400:
                return status, resp
        decisions = self._inspect_completion(resp, session)
        if normalize_fc:
            gigachat_to_openai_response(resp)
        resp["axisec"] = {"decisions": decisions}
        return status, resp

    def _mask_message(self, m: dict, session: str) -> dict:
        content = m.get("content")
        if not isinstance(content, str):
            return m
        masked, types = self.engine.scan_text(content, "requests")
        if not types:
            return m
        self.audit.record(channel="llm", tool="(запрос к модели)", args={"role": m.get("role")}, action="mask",
                          rule="dlp.request", reason="Скрыто перед отправкой в модель: " + ", ".join(types),
                          owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session)
        return {**m, "content": masked}

    def _evaluate_call(self, name: str, raw_args: Any, session: str) -> tuple[Decision, Any]:
        args = raw_args
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args or "{}")
            except ValueError:
                d = Decision("block", name, "args.json", "Аргументы вызова не являются корректным JSON")
                self._log("llm", d, {"raw": raw_args[:200]}, session)
                return d, None
        d = self.engine.evaluate(name, args)
        self._log("llm", d, args, session)
        return d, args

    def _inspect_completion(self, resp: dict, session: str) -> list[dict]:
        decisions: list[dict] = []
        for choice in resp.get("choices") or []:
            msg = choice.get("message") or {}
            notices: list[str] = []
            kept: list[dict] = []
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                d, _ = self._evaluate_call(fn.get("name", ""), fn.get("arguments"), session)
                decisions.append(d.to_dict())
                if d.blocked:
                    notices.append(_notice(d))
                    continue
                if d.new_args is not None:
                    fn["arguments"] = json.dumps(d.new_args, ensure_ascii=False)
                kept.append(call)
            legacy = msg.get("function_call")  # формат GigaChat и старого OpenAI API
            if isinstance(legacy, dict):
                d, _ = self._evaluate_call(legacy.get("name", ""), legacy.get("arguments"), session)
                decisions.append(d.to_dict())
                if d.blocked:
                    notices.append(_notice(d))
                    msg.pop("function_call", None)
                elif d.new_args is not None:
                    as_text = isinstance(legacy.get("arguments"), str)
                    legacy["arguments"] = json.dumps(d.new_args, ensure_ascii=False) if as_text else d.new_args
            if notices:
                if kept:
                    msg["tool_calls"] = kept
                else:
                    msg.pop("tool_calls", None)
                    if not msg.get("function_call"):
                        choice["finish_reason"] = "stop"
                msg["content"] = "\n".join(filter(None, [msg.get("content"), *notices]))
            if isinstance(msg.get("content"), str):
                masked, types = self.engine.scan_text(msg["content"], "responses")
                if types:
                    msg["content"] = masked
                    self.audit.record(channel="llm", tool="(ответ модели)", args={}, action="mask",
                                      rule="dlp.response", reason="Скрыто в ответе модели: " + ", ".join(types),
                                      owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session)
        return decisions

    # ------------------------------------------------------------------ MCP
    async def mcp(self, server: str, payload: Any, session: str = "",
                  headers: dict[str, str] | None = None) -> tuple[int, Any, dict[str, str]]:
        upstream = self.mcp_upstreams.get(server)
        if upstream is None:
            return 404, {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32000, "message": f"MCP-сервер «{server}» не настроен"}}, {}
        batch = payload if isinstance(payload, list) else [payload]
        out, extra = [], {}
        for msg in batch:
            if not isinstance(msg, dict):
                continue
            resp, hdrs = await self._mcp_one(upstream, msg, session, headers or {})
            extra.update(hdrs)
            if resp is not None:
                out.append(resp)
        if not out:
            return 202, None, extra
        return 200, (out if isinstance(payload, list) else out[0]), extra

    async def _mcp_one(self, upstream: str, msg: dict, session: str, headers: dict[str, str]):
        method = msg.get("method")
        if method == "tools/call":
            params = msg.get("params") or {}
            name, args = params.get("name", ""), params.get("arguments") or {}
            d = self.engine.evaluate(name, args)
            self._log("mcp", d, args, session)
            if d.blocked:
                return {"jsonrpc": "2.0", "id": msg.get("id"),
                        "result": {"content": [{"type": "text", "text": _notice(d)}], "isError": True}}, {}
            if d.new_args is not None:
                msg = {**msg, "params": {**params, "arguments": d.new_args}}
        resp, hdrs = await self._forward(upstream, msg, headers)
        if resp is None or "result" not in resp:
            return resp, hdrs
        result = resp["result"]
        if method == "tools/list" and isinstance(result.get("tools"), list):
            hidden_tools = [t.get("name", "") for t in result["tools"] if not self.engine.tool_visible(t.get("name", ""))]
            result["tools"] = [t for t in result["tools"] if self.engine.tool_visible(t.get("name", ""))]
            if hidden_tools:
                self.audit.record(channel="mcp", tool="tools/list", args={}, action="hide", rule="tool.hidden",
                                  reason="Скрыты от агента: " + ", ".join(hidden_tools),
                                  owasp=["LLM06:2025 Excessive Agency", "ASI03 Identity & Privilege Abuse"],
                                  session=session)
        if method == "tools/call":
            hidden: set[str] = set()
            for item in result.get("content") or []:
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    item["text"], types = self.engine.scan_text(item["text"], "responses")
                    hidden.update(types)
            if hidden:
                self.audit.record(channel="mcp", tool=(msg.get("params") or {}).get("name", ""), args={},
                                  action="mask", rule="dlp.response",
                                  reason="Скрыто в ответе инструмента: " + ", ".join(sorted(hidden)),
                                  owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session)
        return resp, hdrs

    async def _forward(self, upstream: str, msg: dict, headers: dict[str, str]):
        if upstream == DEMO:
            return mcp_server.handle(self.world, msg), {}
        fwd = {k: v for k, v in headers.items() if k.lower() in _PASS_HEADERS}
        fwd.setdefault("accept", "application/json, text/event-stream")
        r = await self.http.post(upstream, json=msg, headers=fwd)
        back = {k: r.headers[k] for k in ("mcp-session-id",) if k in r.headers}
        if r.status_code == 202 or not r.content:
            return None, back
        if "text/event-stream" in r.headers.get("content-type", ""):
            for line in r.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[5:].strip())
                    except ValueError:
                        continue
                    if isinstance(data, dict) and data.get("id") == msg.get("id"):
                        return data, back
            return None, back
        try:
            return r.json(), back
        except ValueError:
            return {"jsonrpc": "2.0", "id": msg.get("id"),
                    "error": {"code": -32000, "message": "MCP-сервер вернул не JSON"}}, back
