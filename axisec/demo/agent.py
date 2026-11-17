"""Демо-агент: обычный цикл «модель -> инструменты -> модель» поверх OpenAI API и MCP."""

from __future__ import annotations

import json

import httpx

SYSTEM_PROMPT = ("Ты агент поддержки интернет-магазина «Ромашка». Помогай сотрудникам: "
                 "ищи данные в CRM, меняй статусы заказов, оформляй возвраты.")


async def _rpc(client: httpx.AsyncClient, url: str, method: str, params: dict | None, msg_id: int) -> dict:
    payload = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}
    r = await client.post(url, json=payload, headers={"accept": "application/json, text/event-stream"})
    r.raise_for_status()
    return r.json()


async def run_agent(client: httpx.AsyncClient, llm_url: str, mcp_url: str, prompt: str,
                    session: str = "", max_steps: int = 8) -> dict:
    """Возвращает шаги агента и весь текст, который он получил от инструментов и модели."""
    headers = {"x-axisec-session": session} if session else {}
    listed = await _rpc(client, mcp_url, "tools/list", None, 1)
    tools = [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                               "parameters": t.get("inputSchema", {})}}
             for t in listed.get("result", {}).get("tools", [])]
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
    steps: list[dict] = []
    saw: list[str] = []
    for i in range(max_steps):
        r = await client.post(f"{llm_url}/chat/completions", headers=headers,
                              json={"model": "mock-obedient-1", "messages": messages, "tools": tools})
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        messages.append(msg)
        calls = msg.get("tool_calls") or []
        if not calls:
            content = msg.get("content") or ""
            saw.append(content)
            steps.append({"type": "answer", "content": content})
            break
        for call in calls:
            name = call["function"]["name"]
            args = json.loads(call["function"]["arguments"] or "{}")
            payload = {"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                       "params": {"name": name, "arguments": args}}
            resp = (await client.post(mcp_url, json=payload, headers=headers)).json()
            result = resp.get("result") or {"content": [{"type": "text", "text": str(resp.get("error"))}],
                                            "isError": True}
            text = " ".join(c.get("text", "") for c in result.get("content", []))
            saw.append(text)
            steps.append({"type": "tool", "tool": name, "args": args, "result": text[:700],
                          "error": bool(result.get("isError"))})
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": text})
    return {"steps": steps, "saw": "\n".join(saw)}
