"""Журнал аудита: все решения шлюза, SQLite-персистентность, экспорт в JSONL/CEF и метрики."""

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
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=3000")
            self._db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, data TEXT)")
            self._db.commit()
            rows = self._db.execute("SELECT id, data FROM events ORDER BY id DESC LIMIT ?", (keep,)).fetchall()
            for row_id, raw_json in reversed(rows):
                try:
                    ev = json.loads(raw_json)
                except ValueError:
                    continue
                self._events.append(ev)
                self._seq = max(self._seq, int(ev.get("id", row_id)), int(row_id))

    def record(
        self,
        *,
        channel: str,
        tool: str,
        args: Any,
        action: str,
        rule: str = "",
        reason: str = "",
        owasp: list[str] | None = None,
        latency_us: float = 0.0,
        session: str = "",
        source: str = "",
    ) -> dict:
        with self._lock:
            self._seq += 1
            event = {
                "id": self._seq,
                "ts": time.time(),
                "channel": channel,
                "session": session,
                "source": source,
                "tool": tool,
                "args": _shorten(args),
                "action": action,
                "rule": rule,
                "reason": reason,
                "owasp": owasp or [],
                "latency_us": round(latency_us, 1),
            }
            self._events.append(event)
            if self._db is not None:
                self._db.execute(
                    "INSERT INTO events (ts, data) VALUES (?, ?)",
                    (event["ts"], json.dumps(event, ensure_ascii=False)),
                )
                self._db.commit()
        self.publish(event)
        return event

    def publish(self, payload: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def events(
        self,
        limit: int = 200,
        *,
        action: str = "",
        channel: str = "",
        tool: str = "",
        session: str = "",
        source: str = "",
    ) -> list[dict]:
        with self._lock:
            items = list(self._events)
        if action:
            items = [e for e in items if e.get("action") == action]
        if channel:
            items = [e for e in items if e.get("channel") == channel]
        if tool:
            items = [e for e in items if e.get("tool") == tool]
        if session:
            items = [e for e in items if e.get("session") == session]
        if source:
            items = [e for e in items if e.get("source") == source]
        return items[-limit:][::-1]

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            if self._db is not None:
                self._db.execute("DELETE FROM events")
                self._db.commit()

    def stats(self) -> dict:
        with self._lock:
            events = list(self._events)
        actions = Counter(e["action"] for e in events)
        risk_actions = {"block", "would_block"}
        rules = Counter(e["rule"] for e in events if e["action"] in risk_actions and e.get("rule"))
        owasp = Counter(tag for e in events if e["action"] in risk_actions for tag in e.get("owasp", []))
        lat = sorted(e["latency_us"] for e in events if e.get("latency_us", 0) > 0)

        def pct(p: float) -> float:
            return round(lat[min(len(lat) - 1, int(len(lat) * p))], 1) if lat else 0.0

        return {
            "total": len(events),
            "actions": dict(actions),
            "top_rules": rules.most_common(8),
            "owasp": owasp.most_common(8),
            "latency_us": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99)},
        }

    def export_jsonl(self, limit: int = 1000) -> str:
        rows = self.events(limit)[::-1]
        return "\n".join(json.dumps(e, ensure_ascii=False) for e in rows) + ("\n" if rows else "")

    def export_cef(self, limit: int = 1000) -> str:
        rows = self.events(limit)[::-1]
        lines = []
        for e in rows:
            act = e.get("action", "")
            sev = 8 if act in ("block", "would_block") else (5 if act in ("approve", "mask", "hide", "modify") else 2)
            sig = _cef_hdr(e.get("rule") or act or "decision")
            name = _cef_hdr(e.get("tool") or "unknown")
            ext = " ".join([
                f"act={_cef_val(act)}",
                f"cs1={_cef_val(e.get('channel', ''))}",
                "cs1Label=channel",
                f"cs2={_cef_val(','.join(e.get('owasp', [])))}",
                "cs2Label=owasp",
                f"cs3={_cef_val(e.get('source', ''))}",
                "cs3Label=role",
                f"rt={int(e.get('ts', 0) * 1000)}",
                f"msg={_cef_val(e.get('reason', ''))}",
            ])
            lines.append(f"CEF:0|Axisec|Gateway|0.2.0|{sig}|{name}|{sev}|{ext}")
        return "\n".join(lines) + ("\n" if lines else "")

    def prometheus_metrics(self, pending_approvals: int = 0) -> str:
        with self._lock:
            events = list(self._events)
        by_act_ch = Counter((e.get("action", ""), e.get("channel", "")) for e in events)
        by_rule = Counter(e.get("rule", "") for e in events if e.get("action") in ("block", "would_block") and e.get("rule"))
        lat = sorted(e["latency_us"] for e in events if e.get("latency_us", 0) > 0)

        def pct(p: float) -> float:
            return round(lat[min(len(lat) - 1, int(len(lat) * p))], 1) if lat else 0.0

        out = [
            "# HELP axisec_decisions_total Total gateway decisions by action and channel",
            "# TYPE axisec_decisions_total counter",
        ]
        for (act, ch), cnt in sorted(by_act_ch.items()):
            out.append(f'axisec_decisions_total{{action="{_prom(act)}",channel="{_prom(ch)}"}} {cnt}')
        out.extend([
            "# HELP axisec_blocked_rules_total Blocked calls grouped by policy rule",
            "# TYPE axisec_blocked_rules_total counter",
        ])
        for rule, cnt in sorted(by_rule.items()):
            out.append(f'axisec_blocked_rules_total{{rule="{_prom(rule)}"}} {cnt}')
        out.extend([
            "# HELP axisec_latency_us Engine decision latency in microseconds",
            "# TYPE axisec_latency_us gauge",
            f'axisec_latency_us{{quantile="0.5"}} {pct(0.5)}',
            f'axisec_latency_us{{quantile="0.95"}} {pct(0.95)}',
            f'axisec_latency_us{{quantile="0.99"}} {pct(0.99)}',
            "# HELP axisec_approvals_pending Pending human approval requests",
            "# TYPE axisec_approvals_pending gauge",
            f"axisec_approvals_pending {pending_approvals}",
        ])
        return "\n".join(out) + "\n"

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


def _cef_hdr(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_val(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def _prom(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def _shorten(args: Any, limit: int = 600) -> Any:
    text = json.dumps(args, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return args
    return {"_truncated": text[:limit] + "…"}
