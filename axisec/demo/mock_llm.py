"""Имитатор языковой модели для стенда.

Это намеренно худший случай: «послушная» модель, которая выполняет любую
инструкцию, найденную в сообщении пользователя или в результате инструмента
(так выглядит успешная промпт-инъекция). Защита шлюза не должна зависеть от
стойкости модели, поэтому проверяем её на модели, которая не сопротивляется вовсе.

Формат запросов и ответов совместим с OpenAI Chat Completions.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from urllib.parse import quote

REFUND_ACCOUNT = "40702810900000000001"

_SQL_FENCE = re.compile(r"```sql\s*(.+?)```", re.S | re.I)
_SQL_LINE = re.compile(r"(?im)^\s*SQL:\s*(.+)$")
_DOC = re.compile(r"(?i)(?:прочитай|открой|изучи)\s+(?:документ|файл)\s+([\w\-./]+\.\w+)")
_MAIL_RESULT = re.compile(r"(?i)(?:отправь|перешли)\s+(?:результат|данные|это|всё)\s+на\s+(?:почту\s+|адрес\s+)?([\w.+-]+@[\w.-]+)")
_MAIL_TEXT = re.compile(r"(?i)(?:отправь|напиши)\s+письмо\s+на\s+([\w.+-]+@[\w.-]+)\s*:\s*(.+)")
_HTTP = re.compile(r"(?i)(?:сделай|выполни|отправь)\s+(?:запрос|GET)\s+(?:на\s+)?(\S+://\S+)")
_TRANSFER = re.compile(r"(?i)переведи\s+([\d\s]+)\s*(?:руб\w*|₽)\s+на\s+сч[её]т\s+(\d{10,})")
_DELETE_CUSTOMER = re.compile(r"(?i)удали\s+клиента\s+(\d+)")
# обычные рабочие просьбы
_ORDERS_OF = re.compile(r"(?i)заказы\s+клиента\s+(\d+)")
_ORDER_STATUS = re.compile(r"(?i)статус\s+заказа\s+(\d+)")
_COUNT_CUSTOMERS = re.compile(r"(?i)сколько\s+(?:у\s+нас\s+)?клиентов")
_CLOSE_TICKET = re.compile(r"(?i)закрой\s+обращение\s+(\d+)")
_SHIP_ORDER = re.compile(r"(?i)отметь\s+заказ\s+(\d+)\s+как\s+отправленный")
_REFUND = re.compile(r"(?i)верни\s+([\d\s]+)\s*(?:руб\w*|₽)")
_DELIVERY = re.compile(r"(?i)доставк\w+\s+заказа\s+(\d+)")


def _directives(text: str, last_result: str) -> list[tuple[int, str, dict]]:
    """Находит в тексте все «приказы» и возвращает их в порядке появления."""
    found: list[tuple[int, str, dict]] = []

    def add(m: re.Match, tool: str, args: dict) -> None:
        found.append((m.start(), tool, args))

    for m in _SQL_FENCE.finditer(text):
        add(m, "run_sql", {"query": m.group(1).strip()})
    for m in _SQL_LINE.finditer(text):
        add(m, "run_sql", {"query": m.group(1).strip()})
    for m in _DOC.finditer(text):
        add(m, "read_document", {"name": m.group(1)})
    for m in _MAIL_RESULT.finditer(text):
        add(m, "send_email", {"to": m.group(1).rstrip("."), "subject": "Данные", "body": last_result[:3000]})
    for m in _MAIL_TEXT.finditer(text):
        add(m, "send_email", {"to": m.group(1), "subject": "Сообщение", "body": m.group(2).strip()})
    for m in _HTTP.finditer(text):
        url = m.group(1).rstrip(".,)")
        add(m, "http_request", {"method": "GET", "url": url.replace("{data}", quote(last_result[:400]))})
    for m in _TRANSFER.finditer(text):
        add(m, "transfer_money", {"amount": int(re.sub(r"\s", "", m.group(1))), "currency": "RUB",
                                  "to_account": m.group(2)})
    for m in _DELETE_CUSTOMER.finditer(text):
        add(m, "delete_customer", {"customer_id": int(m.group(1))})
    for m in _ORDERS_OF.finditer(text):
        add(m, "run_sql", {"query": f"SELECT id, item, amount, status FROM orders WHERE customer_id = {m.group(1)} "
                                    "ORDER BY created_at DESC LIMIT 10"})
    for m in _ORDER_STATUS.finditer(text):
        add(m, "run_sql", {"query": f"SELECT id, status, amount FROM orders WHERE id = {m.group(1)}"})
    for m in _COUNT_CUSTOMERS.finditer(text):
        add(m, "run_sql", {"query": "SELECT COUNT(*) AS customers FROM customers"})
    for m in _CLOSE_TICKET.finditer(text):
        add(m, "run_sql", {"query": f"UPDATE tickets SET status = 'closed' WHERE id = {m.group(1)}"})
    for m in _SHIP_ORDER.finditer(text):
        add(m, "run_sql", {"query": f"UPDATE orders SET status = 'shipped' WHERE id = {m.group(1)}"})
    for m in _REFUND.finditer(text):
        add(m, "transfer_money", {"amount": int(re.sub(r"\s", "", m.group(1))), "currency": "RUB",
                                  "to_account": REFUND_ACCOUNT, "comment": "Возврат клиенту"})
    for m in _DELIVERY.finditer(text):
        add(m, "http_request", {"method": "GET", "url": f"https://api.romashka.example/v1/delivery/{m.group(1)}"})
    found.sort(key=lambda x: x[0])
    return found


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def complete(body: dict) -> dict:
    messages = body.get("messages", [])
    available = {t["function"]["name"] for t in body.get("tools", []) if t.get("type") == "function"}
    done = sum(len(m.get("tool_calls") or []) for m in messages if m.get("role") == "assistant")
    last_result = next((_text(m.get("content")) for m in reversed(messages) if m.get("role") == "tool"), "")

    plan: list[tuple[str, dict]] = []
    for m in messages:
        if m.get("role") in ("user", "tool"):
            plan += [(tool, args) for _, tool, args in _directives(_text(m.get("content")), last_result)]

    message: dict = {"role": "assistant", "content": None}
    finish = "stop"
    if done < len(plan) and plan[done][0] in available:
        tool, args = plan[done]
        message["tool_calls"] = [{"id": "call_" + uuid.uuid4().hex[:12], "type": "function",
                                  "function": {"name": tool, "arguments": json.dumps(args, ensure_ascii=False)}}]
        finish = "tool_calls"
    else:
        message["content"] = ("Готово. " + last_result[:600]) if last_result else "Чем могу помочь?"
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:16], "object": "chat.completion", "created": int(time.time()),
        "model": body.get("model", "mock-obedient-1"),
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
