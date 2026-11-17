"""Движок принятия решений: вызов инструмента -> разрешить / изменить / заблокировать."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .guards import dlp
from .guards.args import check_args
from .policy import Policy

# Привязка сработавшего правила к классификаторам OWASP
# (Top 10 for LLM Applications 2025 и Top 10 for Agentic Applications 2026).
_OWASP = [
    ("tool.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("sql.table", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.column", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.star", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.system_catalog", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.limit", ["LLM02:2025 Sensitive Information Disclosure"]),
    ("sql.function", ["LLM06:2025 Excessive Agency", "ASI05 Unexpected Code Execution"]),
    ("sql.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("dlp.", ["LLM02:2025 Sensitive Information Disclosure"]),
    ("args.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
]


def owasp_for(rule: str) -> list[str]:
    for prefix, tags in _OWASP:
        if rule.startswith(prefix):
            return tags
    return []


@dataclass
class Decision:
    action: str  # allow | modify | block
    tool: str
    rule: str = ""
    reason: str = ""
    owasp: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    new_args: dict | None = None
    latency_us: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def to_dict(self) -> dict:
        return asdict(self)


class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def tool_visible(self, tool: str) -> bool:
        tp = self.policy.tools.get(tool)
        if tp is None:
            return self.policy.default_action == "allow"
        return tp.action == "allow"

    def evaluate(self, tool: str, args: Any) -> Decision:
        t0 = time.perf_counter_ns()
        d = self._evaluate(tool, args)
        d.owasp = owasp_for(d.rule) if d.rule else []
        d.latency_us = (time.perf_counter_ns() - t0) / 1000
        return d

    def _evaluate(self, tool: str, args: Any) -> Decision:
        tp = self.policy.tools.get(tool)
        if tp is None:
            if self.policy.default_action == "deny":
                return Decision("block", tool, "tool.unknown",
                                f"Инструмент «{tool}» не описан в политике (запрещено всё, что не разрешено)")
            return Decision("allow", tool)
        if tp.action == "deny":
            return Decision("block", tool, "tool.denied", f"Инструмент «{tool}» запрещён политикой")
        violation, new_args, notes = check_args(args if args is not None else {}, tp)
        if violation is not None:
            return Decision("block", tool, violation.rule, violation.reason, notes=notes)
        if new_args is not None:
            rule = "sql.limit" if any("LIMIT" in n for n in notes) else "dlp.arg"
            return Decision("modify", tool, rule, "; ".join(notes), notes=notes, new_args=new_args)
        return Decision("allow", tool)

    def scan_text(self, text: str, direction: str = "responses") -> tuple[str, list[str]]:
        """Маскирует чувствительные данные. direction: responses | requests."""
        mode = getattr(self.policy.dlp, direction)
        if mode == "off" or not text:
            return text, []
        masked, findings = dlp.mask(text, self.policy.dlp.detectors)
        return masked, sorted({f.type for f in findings})
