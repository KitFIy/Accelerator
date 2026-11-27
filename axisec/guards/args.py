"""Проверка аргументов вызова инструмента по правилам политики."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..policy import ArgRule, PathRules, ShellRules, ToolPolicy
from . import dlp
from .path import check_path
from .shell import check_shell
from .sql import check_sql

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


@dataclass
class Violation:
    rule: str
    reason: str
    action: str = "block"  # block | approve


def _host_allowed(host: str, allow: list[str]) -> bool:
    for entry in allow:
        entry = entry.lower()
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def _check_url(name: str, value: str, rule: ArgRule) -> Violation | None:
    if any(ch.isspace() or ord(ch) < 32 for ch in value) or "\\" in value:
        return Violation(f"args.{name}.url", "URL содержит недопустимые символы")
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        _ = parts.port
    except ValueError:
        return Violation(f"args.{name}.url", "URL не разобран")
    if parts.scheme.lower() not in rule.allow_schemes:
        return Violation(f"args.{name}.scheme", f"Схема «{parts.scheme}» не разрешена")
    if not host or parts.username is not None or parts.password is not None:
        return Violation(f"args.{name}.url", "URL без хоста или с данными авторизации внутри адреса")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return Violation(f"args.{name}.url", "Имя хоста не приводится к ASCII")
    is_ip = True
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        is_ip = False
    allow = rule.allow_hosts
    if allow is not None and not _host_allowed(host, allow):
        kind = "IP-адрес" if is_ip else "Хост"
        return Violation(f"args.{name}.host", f"{kind} «{host}» не входит в список разрешённых адресатов")
    return None


def _type_ok(value: Any, t: str) -> bool:
    if t in ("string", "url", "email", "sql", "shell", "path"):
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "array":
        return isinstance(value, list)
    if t == "object":
        return isinstance(value, dict)
    return False


def check_args(args: Any, tool: ToolPolicy) -> tuple[Violation | None, dict | None, list[str]]:
    """Возвращает (нарушение | None, изменённые аргументы | None, заметки)."""
    if not isinstance(args, dict):
        return Violation("args.type", "Аргументы вызова должны быть объектом"), None, []
    notes: list[str] = []
    new_args: dict | None = None
    pending_approval: Violation | None = None

    if not tool.allow_extra_args:
        extra = sorted(set(args) - set(tool.args))
        if extra:
            return Violation("args.extra", f"Неописанные аргументы: {', '.join(extra)}"), None, notes
    for name, rule in tool.args.items():
        if rule.required and name not in args:
            return Violation(f"args.{name}.required", f"Нет обязательного аргумента «{name}»"), None, notes

    for name, value in args.items():
        rule = tool.args.get(name)
        if rule is None:
            continue
        if not _type_ok(value, rule.type):
            return Violation(f"args.{name}.type", f"Аргумент «{name}» должен иметь тип {rule.type}"), None, notes
        if rule.enum is not None and value not in rule.enum:
            return Violation(f"args.{name}.enum", f"Значение «{name}» не из разрешённого списка"), None, notes
        if rule.type in ("integer", "number"):
            if value != value or value in (float("inf"), float("-inf")):
                return Violation(f"args.{name}.type", f"Аргумент «{name}» не является числом"), None, notes
            if rule.min is not None and value < rule.min:
                return Violation(f"args.{name}.min", f"«{name}» = {value} меньше допустимого {rule.min:g}"), None, notes
            if rule.max is not None and value > rule.max:
                return Violation(f"args.{name}.max", f"«{name}» = {value} больше допустимого {rule.max:g}"), None, notes
            if rule.approve_above is not None and value > rule.approve_above and pending_approval is None:
                pending_approval = Violation(
                    f"args.{name}.approve_above",
                    f"«{name}» = {value} превышает порог {rule.approve_above:g} и требует подтверждения",
                    action="approve",
                )
        if isinstance(value, str):
            if rule.max_length is not None and len(value) > rule.max_length:
                return Violation(f"args.{name}.max_length",
                                 f"«{name}» длиннее {rule.max_length} символов"), None, notes
            if rule.pattern is not None and re.fullmatch(rule.pattern, value) is None:
                return Violation(f"args.{name}.pattern", f"«{name}» не соответствует разрешённому формату"), None, notes
        if rule.type == "url":
            v = _check_url(name, value, rule)
            if v:
                return v, None, notes
        if rule.type == "email":
            m = _EMAIL.fullmatch(value.strip())
            if m is None:
                return Violation(f"args.{name}.email", f"«{name}» не является адресом почты"), None, notes
            if rule.allow_hosts is not None and not _host_allowed(m.group(1).lower(), rule.allow_hosts):
                return Violation(f"args.{name}.host",
                                 f"Домен получателя «{m.group(1).lower()}» не входит в список разрешённых"), None, notes
        if rule.type == "sql":
            verdict = check_sql(value, rule.sql) if rule.sql is not None else None
            if verdict is None:
                return Violation(f"args.{name}.sql", "Для SQL-аргумента не заданы правила"), None, notes
            if not verdict.ok:
                return Violation(verdict.rule, verdict.reason), None, notes
            if verdict.rule == "sql.approve" and pending_approval is None:
                pending_approval = Violation("sql.approve", verdict.reason, action="approve")
            if verdict.new_sql is not None:
                new_args = dict(new_args or args)
                new_args[name] = verdict.new_sql
                notes.append(f"В запрос добавлено ограничение LIMIT {rule.sql.max_rows}")
        if rule.type == "shell":
            s_verdict = check_shell(value, rule.shell or ShellRules())
            if not s_verdict.ok:
                return Violation(s_verdict.rule, s_verdict.reason), None, notes
        if rule.type == "path":
            p_verdict = check_path(value, rule.path or PathRules())
            if not p_verdict.ok:
                return Violation(p_verdict.rule, p_verdict.reason), None, notes
        if rule.dlp != "off":
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            findings = dlp.scan(text, rule.dlp_detectors)
            if findings:
                types = ", ".join(sorted({f.type for f in findings}))
                if rule.dlp == "block":
                    return Violation(f"dlp.arg.{name}",
                                     f"В аргументе «{name}» найдены чувствительные данные: {types}"), None, notes
                if isinstance(value, str):
                    new_args = dict(new_args or args)
                    new_args[name] = dlp.mask(value, rule.dlp_detectors)[0]
                    notes.append(f"В аргументе «{name}» скрыты данные: {types}")
    if pending_approval is not None:
        return pending_approval, new_args, notes
    return None, new_args, notes
