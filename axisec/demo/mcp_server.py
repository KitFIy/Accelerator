"""Минимальный MCP-сервер стенда (транспорт Streamable HTTP, ответы в JSON)."""

from __future__ import annotations

from .world import TOOLS, World

SERVER_INFO = {"name": "romashka-crm", "version": "1.0.0"}
FALLBACK_PROTOCOL = "2025-06-18"


def handle(world: World, msg: dict) -> dict | None:
    """Обрабатывает одно сообщение JSON-RPC. Для уведомлений возвращает None."""
    method, msg_id = msg.get("method"), msg.get("id")
    if msg_id is None:
        return None
    if method == "initialize":
        version = (msg.get("params") or {}).get("protocolVersion") or FALLBACK_PROTOCOL
        result = {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": SERVER_INFO}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        text, is_error = world.call(params.get("name", ""), params.get("arguments") or {})
        result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    else:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}
