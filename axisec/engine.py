"""Движок принятия решений: вызов инструмента -> разрешить / изменить / подтвердить / заблокировать."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .guards import dlp
from .guards.args import check_args
from .policy import Policy, ToolPolicy

# Привязка сработавшего правила к классификаторам OWASP
# (Top 10 for LLM Applications 2025 и Top 10 for Agentic Applications 2026).
_OWASP = [
    ("rbac.", ["LLM06:2025 Excessive Agency", "ASI03 Identity & Privilege Abuse"]),
    ("approval.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("tool.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("sql.table", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.column", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.star", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.system_catalog", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
    ("sql.limit", ["LLM02:2025 Sensitive Information Disclosure"]),
    ("sql.approve", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("sql.function", ["LLM06:2025 Excessive Agency", "ASI05 Unexpected Code Execution"]),
    ("sql.", ["LLM06:2025 Excessive Agency", "ASI02 Tool Misuse"]),
    ("shell.", ["LLM06:2025 Excessive Agency", "ASI05 Unexpected Code Execution"]),
    ("path.", ["LLM02:2025 Sensitive Information Disclosure", "ASI03 Identity & Privilege Abuse"]),
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
    action: str  # allow | modify | approve | block
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

    @property
    def needs_approval(self) -> bool:
        return self.action == "approve"

    def to_dict(self) -> dict:
        return asdict(self)


def _merge_policy_for_role(base: Policy, role_name: str) -> Policy:
    role = base.roles[role_name]
    tools: dict[str, ToolPolicy] = dict(base.tools)
    for name, tp in role.tools.items():
        tools[name] = tp
    if role.allow_tools is not None:
        allowed = set(role.allow_tools)
        for name in list(tools):
            if name not in allowed:
                tools[name] = ToolPolicy(description=tools[name].description, action="deny")
    for name in role.deny_tools:
        desc = tools[name].description if name in tools else ""
        tools[name] = ToolPolicy(description=desc, action="deny")
    return Policy(
        version=base.version,
        name=f"{base.name}:{role_name}",
        description=role.description or base.description,
        mode=role.mode or base.mode,
        default_action=role.default_action or base.default_action,
        tools=tools,
        roles={},
        dlp=base.dlp,
    )


class PolicyEngine:
    def __init__(self, policy: Policy, *, observe_override: str | None = None):
        self.policy = policy
        self._observe_override = observe_override
        self._role_engines: dict[str, PolicyEngine] = {
            name: PolicyEngine(_merge_policy_for_role(policy, name), observe_override=observe_override)
            for name in policy.roles
        }

    @property
    def is_observe(self) -> bool:
        mode = self._observe_override or self.policy.mode
        return mode == "observe"

    def resolve_role(self, role: str | None) -> tuple[PolicyEngine | None, str]:
        """Возвращает `(движок_для_роли, ошибка)`. Если роль неизвестна — ошибка (fail-closed)."""
        if not role:
            return self, ""
        sub = self._role_engines.get(role)
        if sub is None:
            if self.policy.roles:
                return None, f"Роль «{role}» не описана в политике"
            return self, ""
        return sub, ""

    def tool_visible(self, tool: str, role: str | None = None) -> bool:
        eng, err = self.resolve_role(role)
        if eng is None or err:
            return False
        if eng.is_observe:
            return True
        tp = eng.policy.tools.get(tool)
        if tp is None:
            return eng.policy.default_action == "allow"
        return tp.action in ("allow", "approve")

    def evaluate(self, tool: str, args: Any, role: str | None = None) -> Decision:
        t0 = time.perf_counter_ns()
        eng, err = self.resolve_role(role)
        if eng is None:
            d = Decision("block", tool, "rbac.unknown_role", err)
        else:
            d = eng._evaluate(tool, args)
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
            if violation.action == "approve":
                return Decision("approve", tool, violation.rule, violation.reason, notes=notes, new_args=new_args)
            return Decision("block", tool, violation.rule, violation.reason, notes=notes)
        if tp.action == "approve":
            return Decision("approve", tool, "approval.tool",
                            f"Вызов «{tool}» требует подтверждения человеком", notes=notes, new_args=new_args)
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
