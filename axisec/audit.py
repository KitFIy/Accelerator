"""Журнал аудита: все решения шлюза. Хранится в памяти и, если задан путь, в SQLite."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, db_path: str | Path | None = None, keep: int = 5000):
        self._events: deque[dict] = deque(maxlen=keep)
        self._lock = threading.Lock()
        self._seq = 0
        self._subscribers: set[asyncio.Queue] = set()
        self._db: sqlite3.Connection | None = None
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(db_path), check_same_thread=False)
            self._db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, data TEXT)")
            self._db.commit()

    def record(self, *, channel: str, tool: str, args: Any, action: str, rule: str = "", reason: str = "",
               owasp: list[str] | None = None, latency_us: float = 0.0, session: str = "", source: str = "") -> dict:
        with self._lock:
            self._seq += 1
            event = {
                "id": self._seq, "ts": time.time(), "channel": channel, "session": session, "source": source,
                "tool": tool, "args": _shorten(args), "action": action, "rule": rule, "reason": reason,
                "owasp": owasp or [], "latency_us": round(latency_us, 1),
            }
            self._events.append(event)
            if self._db is not None:
                self._db.execute("INSERT INTO events (ts, data) VALUES (?, ?)",
                                 (event["ts"], json.dumps(event, ensure_ascii=False)))
                self._db.commit()
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
        return event

    def events(self, limit: int = 200) -> list[dict]:
        with self._lock:
            return list(self._events)[-limit:][::-1]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def stats(self) -> dict:
        with self._lock:
            events = list(self._events)
        actions = Counter(e["action"] for e in events)
        rules = Counter(e["rule"] for e in events if e["action"] == "block")
        owasp = Counter(tag for e in events if e["action"] == "block" for tag in e["owasp"])
        lat = sorted(e["latency_us"] for e in events if e["latency_us"] > 0)

        def pct(p: float) -> float:
            return round(lat[min(len(lat) - 1, int(len(lat) * p))], 1) if lat else 0.0

        return {
            "total": len(events), "actions": dict(actions),
            "top_rules": rules.most_common(8), "owasp": owasp.most_common(8),
            "latency_us": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99)},
        }

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)


def _shorten(args: Any, limit: int = 600) -> Any:
    text = json.dumps(args, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return args
    return {"_truncated": text[:limit] + "…"}
