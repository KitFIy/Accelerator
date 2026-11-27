"""Очередь подтверждения действий человеком (Human-in-the-Loop)."""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ApprovalItem:
    id: str
    ts: float
    channel: str
    tool: str
    args: Any
    rule: str
    reason: str
    owasp: list[str] = field(default_factory=list)
    session: str = ""
    role: str = ""
    status: str = "pending"  # pending | approved | rejected | expired
    decided_by: str = ""
    decided_at: float | None = None
    _event: asyncio.Event | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "channel": self.channel,
            "tool": self.tool,
            "args": self.args,
            "rule": self.rule,
            "reason": self.reason,
            "owasp": self.owasp,
            "session": self.session,
            "role": self.role,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }


class ApprovalQueue:
    """Хранит запросы на подтверждение и позволяет ждать решения оператора асинхронно."""

    def __init__(self, max_items: int = 500, on_change: Callable[[dict], None] | None = None):
        self._items: dict[str, ApprovalItem] = {}
        self._order: list[str] = []
        self._max_items = max_items
        self._lock = threading.Lock()
        self._on_change = on_change

    def create(
        self,
        *,
        channel: str,
        tool: str,
        args: Any,
        rule: str,
        reason: str,
        owasp: list[str] | None = None,
        session: str = "",
        role: str = "",
    ) -> ApprovalItem:
        try:
            asyncio.get_running_loop()
            ev: asyncio.Event | None = asyncio.Event()
        except RuntimeError:
            ev = None
        item = ApprovalItem(
            id=uuid.uuid4().hex[:10],
            ts=time.time(),
            channel=channel,
            tool=tool,
            args=args,
            rule=rule,
            reason=reason,
            owasp=list(owasp or []),
            session=session,
            role=role,
            _event=ev,
        )
        with self._lock:
            self._items[item.id] = item
            self._order.append(item.id)
            while len(self._order) > self._max_items:
                old_id = self._order.pop(0)
                self._items.pop(old_id, None)
        if self._on_change:
            self._on_change(item.to_dict())
        return item

    def list(self, status: str = "") -> list[dict]:
        with self._lock:
            items = [self._items[i] for i in reversed(self._order) if i in self._items]
        if status:
            items = [it for it in items if it.status == status]
        return [it.to_dict() for it in items]

    def get(self, item_id: str) -> ApprovalItem | None:
        with self._lock:
            return self._items.get(item_id)

    def resolve(self, item_id: str, approved: bool, decided_by: str = "operator") -> dict | None:
        with self._lock:
            item = self._items.get(item_id)
            if item is None:
                return None
            if item.status == "pending":
                item.status = "approved" if approved else "rejected"
                item.decided_by = decided_by
                item.decided_at = time.time()
                if item._event is not None:
                    item._event.set()
            data = item.to_dict()
        if self._on_change:
            self._on_change(data)
        return data

    async def wait(self, item_id: str, timeout_s: float) -> str:
        item = self.get(item_id)
        if item is None:
            return "rejected"
        if item.status != "pending":
            return item.status
        if timeout_s <= 0:
            return "pending"
        if item._event is None:
            item._event = asyncio.Event()
        try:
            await asyncio.wait_for(item._event.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            with self._lock:
                if item.status == "pending":
                    item.status = "expired"
                    item.decided_at = time.time()
            if self._on_change:
                self._on_change(item.to_dict())
        return item.status
