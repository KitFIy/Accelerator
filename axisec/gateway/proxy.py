"""Две точки контроля шлюза.

1. Ответ модели (OpenAI-совместимый Chat Completions, GigaChat, YandexGPT): вызовы
   инструментов проверяются до того, как их увидит и исполнит обвязка агента.
2. MCP (JSON-RPC, метод tools/call): вызов проверяется перед самим ресурсом.

Поддерживаются режим наблюдения (observe), подтверждение человеком (approve),
ролевые политики (RBAC) и потоковая передача SSE.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator

import httpx

from ..approvals import ApprovalQueue
from ..audit import AuditLog
from ..demo import mcp_server, mock_llm
from ..demo.world import World
from ..engine import Decision, PolicyEngine
from ..guards.dlp import StreamMasker
from .providers import ProviderAdapter, ProviderError, gigachat_to_openai_response

DEMO = "demo"
_PASS_HEADERS = ("authorization", "mcp-session-id", "mcp-protocol-version", "accept")


def _notice(d: Decision, prefix: str = "заблокировано") -> str:
    return f"[Axisec] Действие «{d.tool}» {prefix}: {d.reason} (правило {d.rule})."


class Gateway:
    def __init__(
        self,
        engine: PolicyEngine,
        audit: AuditLog,
        world: World,
        http: httpx.AsyncClient,
        llm_upstream: str = DEMO,
        llm_api_key: str = "",
        mcp_upstreams: dict[str, str] | None = None,
        llm_provider: str = "",
        provider_adapter: ProviderAdapter | None = None,
        approvals: ApprovalQueue | None = None,
        approval_wait_s: float | None = None,
    ):
        self.engine, self.audit, self.world, self.http = engine, audit, world, http
        self.llm_upstream, self.llm_api_key = llm_upstream, llm_api_key
        self.mcp_upstreams = mcp_upstreams or {"crm": DEMO}
        self.provider = provider_adapter or ProviderAdapter(llm_upstream, provider=llm_provider, api_key=llm_api_key)
        self.approvals = approvals or ApprovalQueue(on_change=lambda item: audit.publish({"type": "approval", **item}))
        if approval_wait_s is None:
            raw = os.getenv("AXISEC_APPROVAL_WAIT_SECONDS", "30")
            self.approval_wait_s = float(raw) if raw else 30.0
        else:
            self.approval_wait_s = approval_wait_s

    def _log(self, channel: str, d: Decision, args: Any, session: str, role: str = "", action_override: str = "") -> None:
        self.audit.record(
            channel=channel,
            tool=d.tool,
            args=args,
            action=action_override or d.action,
            rule=d.rule,
            reason=d.reason,
            owasp=d.owasp,
            latency_us=d.latency_us,
            session=session,
            source=role,
        )

    def _is_observe(self, role: str = "") -> bool:
        eng, err = self.engine.resolve_role(role)
        return eng.is_observe if (eng is not None and not err) else self.engine.is_observe

    async def _resolve_decision(
        self,
        channel: str,
        d: Decision,
        args: Any,
        session: str,
        role: str = "",
        wait_override: float | None = None,
    ) -> tuple[Decision, str]:
        """Применяет режим observe и human-in-the-loop. Возвращает `(итоговое_решение, audit_action)`."""
        observe = self._is_observe(role)
        if observe:
            if d.action == "block":
                self._log(channel, d, args, session, role, action_override="would_block")
                return Decision("allow", d.tool, d.rule, d.reason, d.owasp, d.notes, None, d.latency_us), "would_block"
            if d.action == "approve":
                self._log(channel, d, args, session, role, action_override="would_approve")
                return Decision("allow", d.tool, d.rule, d.reason, d.owasp, d.notes, None, d.latency_us), "would_approve"
            if d.action == "modify":
                self._log(channel, d, args, session, role, action_override="would_modify")
                return Decision("allow", d.tool, d.rule, d.reason, d.owasp, d.notes, None, d.latency_us), "would_modify"
            self._log(channel, d, args, session, role)
            return d, "allow"

        if d.needs_approval:
            item = self.approvals.create(
                channel=channel, tool=d.tool, args=args, rule=d.rule, reason=d.reason,
                owasp=d.owasp, session=session, role=role,
            )
            self._log(channel, d, args, session, role, action_override="approve")
            wait_s = self.approval_wait_s if wait_override is None else wait_override
            outcome = await self.approvals.wait(item.id, wait_s)
            if outcome == "approved":
                final_action = "modify" if d.new_args is not None else "allow"
                approved_d = Decision(final_action, d.tool, d.rule, f"Подтверждено оператором ({item.id})",
                                      d.owasp, d.notes, d.new_args, d.latency_us)
                self._log(channel, approved_d, args, session, role, action_override="approved")
                return approved_d, "approved"
            why = "отклонено оператором" if outcome == "rejected" else f"ожидает подтверждения (заявка {item.id})"
            blocked_d = Decision("block", d.tool, d.rule, f"{d.reason}; {why}", d.owasp, d.notes, None, d.latency_us)
            self._log(channel, blocked_d, args, session, role)
            return blocked_d, "block"

        self._log(channel, d, args, session, role)
        return d, d.action

    # ------------------------------------------------------------------ модель
    async def chat(
        self,
        body: dict,
        session: str = "",
        authorization: str = "",
        role: str = "",
        wait_override: float | None = None,
    ) -> tuple[int, dict]:
        body = dict(body)
        body.pop("stream", None)
        observe = self._is_observe(role)
        if self.engine.policy.dlp.requests == "mask":
            body["messages"] = [self._mask_message(m, session, role, observe) for m in body.get("messages", [])]
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
        decisions = await self._inspect_completion_async(resp, session, role, wait_override)
        if normalize_fc:
            gigachat_to_openai_response(resp)
        resp["axisec"] = {"decisions": decisions, "mode": "observe" if observe else "enforce"}
        return status, resp

    async def chat_stream(
        self,
        body: dict,
        session: str = "",
        authorization: str = "",
        role: str = "",
        wait_override: float | None = None,
    ) -> tuple[int, AsyncIterator[str] | dict]:
        """Потоковый режим SSE: текстовые дельты идут сразу через StreamMasker, tool_calls буферизуются и проверяются."""
        if self.provider.provider in (DEMO, "gigachat"):
            status, resp = await self.chat(body, session=session, authorization=authorization,
                                           role=role, wait_override=wait_override)
            if status != 200:
                return status, resp
            return 200, _single_sse(resp)

        req_body = dict(body)
        req_body["stream"] = True
        observe = self._is_observe(role)
        if self.engine.policy.dlp.requests == "mask":
            req_body["messages"] = [self._mask_message(m, session, role, observe) for m in req_body.get("messages", [])]

        url, payload, headers, _ = await self.provider.prepare_request(req_body, authorization, self.http)

        async def stream_gen() -> AsyncIterator[str]:
            masker = StreamMasker(self.engine.policy.dlp.detectors) if self.engine.policy.dlp.responses == "mask" else None
            tool_acc: dict[int, dict[str, str]] = {}
            fc_acc: dict[str, str] = {}
            meta: dict[str, Any] = {"id": "", "created": 0, "model": body.get("model", "")}
            last_finish = None

            async with self.http.stream("POST", url, json=payload, headers=headers) as r:
                if r.status_code >= 400:
                    err_body = (await r.aread()).decode("utf-8", errors="replace")
                    yield f"data: {json.dumps({'error': {'message': err_body[:400], 'status': r.status_code}}, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                async for raw_line in r.aiter_lines():
                    line = raw_line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except ValueError:
                        continue
                    for k in ("id", "created", "model"):
                        if chunk.get(k):
                            meta[k] = chunk[k]
                    choices = chunk.get("choices") or []
                    if not choices:
                        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                        continue
                    ch = choices[0]
                    delta = dict(ch.get("delta") or {})
                    if ch.get("finish_reason"):
                        last_finish = ch["finish_reason"]

                    # Буферизуем tool_calls / function_call для полной проверки до отдачи агенту
                    has_tools = False
                    if "tool_calls" in delta and delta["tool_calls"]:
                        has_tools = True
                        for tc in delta["tool_calls"]:
                            idx = int(tc.get("index", 0))
                            slot = tool_acc.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                            if tc.get("id"):
                                slot["id"] = tc["id"]
                            fn = tc.get("function") or {}
                            if fn.get("name"):
                                slot["name"] += fn["name"]
                            if fn.get("arguments"):
                                slot["arguments"] += fn["arguments"]
                    if "function_call" in delta and isinstance(delta["function_call"], dict):
                        has_tools = True
                        fc = delta["function_call"]
                        if fc.get("name"):
                            fc_acc["name"] = fc_acc.get("name", "") + fc["name"]
                        if fc.get("arguments"):
                            fc_acc["arguments"] = fc_acc.get("arguments", "") + str(fc["arguments"])

                    text_piece = delta.get("content")
                    if isinstance(text_piece, str) and text_piece:
                        if masker is not None and not observe:
                            safe_text = masker.feed(text_piece)
                            if safe_text:
                                out_ch = {**ch, "finish_reason": None, "delta": {**{k: v for k, v in delta.items() if k not in ("tool_calls", "function_call")}, "content": safe_text}}
                                yield f"data: {json.dumps({**meta, 'object': 'chat.completion.chunk', 'choices': [out_ch]}, ensure_ascii=False)}\n\n"
                        else:
                            if masker is not None:
                                masker.feed(text_piece)
                            if not has_tools:
                                out_ch = {**ch, "finish_reason": None}
                                yield f"data: {json.dumps({**meta, 'object': 'chat.completion.chunk', 'choices': [out_ch]}, ensure_ascii=False)}\n\n"
                    elif not has_tools and ch.get("finish_reason") is None:
                        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"

            # Сброс остатка текстового буфера
            if masker is not None:
                tail = masker.flush()
                if tail and not observe:
                    yield _delta_sse(meta, {"content": tail}, None)
                if masker.detected:
                    self.audit.record(
                        channel="llm", tool="(поток ответа)", args={},
                        action="would_mask" if observe else "mask",
                        rule="dlp.response",
                        reason="Скрыто в потоке модели: " + ", ".join(sorted(masker.detected)),
                        owasp=["LLM02:2025 Sensitive Information Disclosure"],
                        session=session, source=role,
                    )

            # Проверка собранных вызовов инструментов
            if tool_acc or fc_acc:
                synthetic_msg: dict[str, Any] = {"role": "assistant", "content": ""}
                if tool_acc:
                    synthetic_msg["tool_calls"] = [
                        {"id": v["id"] or f"call_{idx}", "type": "function",
                         "function": {"name": v["name"], "arguments": v["arguments"]}}
                        for idx, v in sorted(tool_acc.items())
                    ]
                if fc_acc:
                    synthetic_msg["function_call"] = fc_acc
                synthetic_resp = {"choices": [{"index": 0, "message": synthetic_msg, "finish_reason": last_finish or "tool_calls"}]}
                await self._inspect_completion_async(synthetic_resp, session, role, wait_override)
                final_choice = synthetic_resp["choices"][0]
                final_msg = final_choice["message"]
                if final_msg.get("content"):
                    yield _delta_sse(meta, {"content": final_msg["content"]}, None)
                if final_msg.get("tool_calls"):
                    for i, c in enumerate(final_msg["tool_calls"]):
                        c["index"] = i
                    yield _delta_sse(meta, {"tool_calls": final_msg["tool_calls"]}, final_choice.get("finish_reason") or "tool_calls")
                elif final_msg.get("function_call"):
                    yield _delta_sse(meta, {"function_call": final_msg["function_call"]}, final_choice.get("finish_reason") or "function_call")
                else:
                    yield _delta_sse(meta, {}, final_choice.get("finish_reason") or "stop")
            else:
                yield _delta_sse(meta, {}, last_finish or "stop")

            yield "data: [DONE]\n\n"

        return 200, stream_gen()

    def _mask_message(self, m: dict, session: str, role: str = "", observe: bool = False) -> dict:
        content = m.get("content")
        if not isinstance(content, str):
            return m
        masked, types = self.engine.scan_text(content, "requests")
        if not types:
            return m
        self.audit.record(
            channel="llm", tool="(запрос к модели)", args={"role": m.get("role")},
            action="would_mask" if observe else "mask",
            rule="dlp.request", reason="Скрыто перед отправкой в модель: " + ", ".join(types),
            owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session, source=role,
        )
        return m if observe else {**m, "content": masked}

    def _parse_and_evaluate(self, name: str, raw_args: Any, role: str = "") -> tuple[Decision, Any]:
        args = raw_args
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args or "{}")
            except ValueError:
                return Decision("block", name, "args.json", "Аргументы вызова не являются корректным JSON"), {"raw": raw_args[:200]}
        return self.engine.evaluate(name, args, role=role), args

    def _finalize_completion_choice(
        self, choice: dict, decisions: list[dict], eval_results: list[tuple[str, Any, Decision, str]],
        session: str, role: str, observe: bool,
    ) -> None:
        msg = choice.get("message") or {}
        notices: list[str] = []
        kept: list[dict] = []
        for kind, ref, d, audit_action in eval_results:
            d_dict = d.to_dict()
            d_dict["audit_action"] = audit_action
            decisions.append(d_dict)
            if kind == "tool_call":
                fn = ref.get("function") or {}
                if d.blocked:
                    notices.append(_notice(d))
                    continue
                if d.new_args is not None:
                    fn["arguments"] = json.dumps(d.new_args, ensure_ascii=False)
                kept.append(ref)
            else:
                if d.blocked:
                    notices.append(_notice(d))
                    msg.pop("function_call", None)
                elif d.new_args is not None:
                    as_text = isinstance(ref.get("arguments"), str)
                    ref["arguments"] = json.dumps(d.new_args, ensure_ascii=False) if as_text else d.new_args
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
                if not observe:
                    msg["content"] = masked
                self.audit.record(
                    channel="llm", tool="(ответ модели)", args={},
                    action="would_mask" if observe else "mask",
                    rule="dlp.response", reason="Скрыто в ответе модели: " + ", ".join(types),
                    owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session, source=role,
                )

    def _inspect_completion(self, resp: dict, session: str = "", role: str = "") -> list[dict]:
        """Синхронная проверка ответа модели (для прямых unit-вызовов без ожидания апрува)."""
        decisions: list[dict] = []
        observe = self._is_observe(role)
        for choice in resp.get("choices") or []:
            msg = choice.get("message") or {}
            evals: list[tuple[str, Any, Decision, str]] = []
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                d, args = self._parse_and_evaluate(fn.get("name", ""), fn.get("arguments"), role)
                act = "would_block" if (observe and d.blocked) else d.action
                if observe and d.action in ("block", "approve", "modify"):
                    act = f"would_{d.action}"
                    self._log("llm", d, args, session, role, action_override=act)
                    d = Decision("allow", d.tool, d.rule, d.reason, d.owasp, d.notes, None, d.latency_us)
                else:
                    self._log("llm", d, args, session, role)
                evals.append(("tool_call", call, d, act))
            legacy = msg.get("function_call")
            if isinstance(legacy, dict):
                d, args = self._parse_and_evaluate(legacy.get("name", ""), legacy.get("arguments"), role)
                act = d.action
                if observe and d.action in ("block", "approve", "modify"):
                    act = f"would_{d.action}"
                    self._log("llm", d, args, session, role, action_override=act)
                    d = Decision("allow", d.tool, d.rule, d.reason, d.owasp, d.notes, None, d.latency_us)
                else:
                    self._log("llm", d, args, session, role)
                evals.append(("function_call", legacy, d, act))
            self._finalize_completion_choice(choice, decisions, evals, session, role, observe)
        return decisions

    async def _inspect_completion_async(
        self, resp: dict, session: str, role: str = "", wait_override: float | None = None
    ) -> list[dict]:
        decisions: list[dict] = []
        observe = self._is_observe(role)
        for choice in resp.get("choices") or []:
            msg = choice.get("message") or {}
            evals: list[tuple[str, Any, Decision, str]] = []
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                raw_d, args = self._parse_and_evaluate(fn.get("name", ""), fn.get("arguments"), role)
                d, act = await self._resolve_decision("llm", raw_d, args, session, role, wait_override)
                evals.append(("tool_call", call, d, act))
            legacy = msg.get("function_call")
            if isinstance(legacy, dict):
                raw_d, args = self._parse_and_evaluate(legacy.get("name", ""), legacy.get("arguments"), role)
                d, act = await self._resolve_decision("llm", raw_d, args, session, role, wait_override)
                evals.append(("function_call", legacy, d, act))
            self._finalize_completion_choice(choice, decisions, evals, session, role, observe)
        return decisions

    # ------------------------------------------------------------------ MCP
    async def mcp(
        self,
        server: str,
        payload: Any,
        session: str = "",
        headers: dict[str, str] | None = None,
        role: str = "",
        wait_override: float | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        upstream = self.mcp_upstreams.get(server)
        if upstream is None:
            return 404, {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32000, "message": f"MCP-сервер «{server}» не настроен"}}, {}
        batch = payload if isinstance(payload, list) else [payload]
        out, extra = [], {}
        for msg in batch:
            if not isinstance(msg, dict):
                continue
            resp, hdrs = await self._mcp_one(upstream, msg, session, headers or {}, role, wait_override)
            extra.update(hdrs)
            if resp is not None:
                out.append(resp)
        if not out:
            return 202, None, extra
        return 200, (out if isinstance(payload, list) else out[0]), extra

    async def mcp_stream(self, server: str, headers: dict[str, str] | None = None) -> tuple[int, AsyncIterator[bytes] | None, dict[str, str]]:
        """Проксирует серверный поток GET /mcp/{server} для реальных MCP-апстримов."""
        upstream = self.mcp_upstreams.get(server)
        if upstream is None:
            return 404, None, {}
        if upstream == DEMO:
            return 405, None, {"allow": "POST"}
        fwd = {k: v for k, v in (headers or {}).items() if k.lower() in _PASS_HEADERS}
        fwd.setdefault("accept", "text/event-stream")
        req = self.http.build_request("GET", upstream, headers=fwd)
        resp = await self.http.send(req, stream=True)
        if resp.status_code >= 400:
            hdrs = {"allow": resp.headers.get("allow", "POST")} if resp.status_code == 405 else {}
            await resp.aclose()
            return resp.status_code, None, hdrs
        back = {k: resp.headers[k] for k in ("mcp-session-id",) if k in resp.headers}

        async def body_iter() -> AsyncIterator[bytes]:
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()

        return resp.status_code, body_iter(), back

    async def list_upstream_tools(self, server: str) -> list[dict]:
        """Запрашивает `tools/list` напрямую у MCP-сервера (для автогенерации черновика политики)."""
        upstream = self.mcp_upstreams.get(server)
        if upstream is None:
            raise KeyError(server)
        resp, _ = await self._forward(upstream, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, {})
        return list(((resp or {}).get("result") or {}).get("tools") or [])

    async def _mcp_one(
        self, upstream: str, msg: dict, session: str, headers: dict[str, str], role: str = "", wait_override: float | None = None
    ):
        method = msg.get("method")
        observe = self._is_observe(role)
        if method == "tools/call":
            params = msg.get("params") or {}
            name, args = params.get("name", ""), params.get("arguments") or {}
            d = self.engine.evaluate(name, args, role=role)
            d, _ = await self._resolve_decision("mcp", d, args, session, role, wait_override)
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
            eng, err = self.engine.resolve_role(role)
            if eng is None or err:
                hidden_tools = [t.get("name", "") for t in result["tools"]]
                if not observe:
                    result["tools"] = []
            else:
                # В режиме observe tool_visible возвращает True — проверяем строгую видимость отдельно для лога
                strict_hidden = []
                for t in result["tools"]:
                    tname = t.get("name", "")
                    tp = eng.policy.tools.get(tname)
                    visible = (eng.policy.default_action == "allow") if tp is None else (tp.action in ("allow", "approve"))
                    if not visible:
                        strict_hidden.append(tname)
                hidden_tools = strict_hidden
                if not observe:
                    result["tools"] = [t for t in result["tools"] if t.get("name", "") not in set(strict_hidden)]
            if hidden_tools:
                self.audit.record(
                    channel="mcp", tool="tools/list", args={},
                    action="would_hide" if observe else "hide",
                    rule="tool.hidden",
                    reason="Скрыты от агента: " + ", ".join(hidden_tools),
                    owasp=["LLM06:2025 Excessive Agency", "ASI03 Identity & Privilege Abuse"],
                    session=session, source=role,
                )
        if method == "tools/call":
            hidden: set[str] = set()
            for item in result.get("content") or []:
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    masked, types = self.engine.scan_text(item["text"], "responses")
                    if types and not observe:
                        item["text"] = masked
                    hidden.update(types)
            if hidden:
                self.audit.record(
                    channel="mcp", tool=(msg.get("params") or {}).get("name", ""), args={},
                    action="would_mask" if observe else "mask",
                    rule="dlp.response",
                    reason="Скрыто в ответе инструмента: " + ", ".join(sorted(hidden)),
                    owasp=["LLM02:2025 Sensitive Information Disclosure"], session=session, source=role,
                )
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


def _delta_sse(meta: dict, delta: dict, finish_reason: str | None) -> str:
    chunk = {
        "id": meta.get("id") or "chatcmpl-axisec",
        "created": meta.get("created") or 0,
        "model": meta.get("model") or "",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }
    return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"


async def _single_sse(resp: dict) -> AsyncIterator[str]:
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
