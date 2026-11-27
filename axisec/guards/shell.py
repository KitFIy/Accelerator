"""Проверка shell-команд через лексический разбор (shlex), а не регулярные выражения."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..policy import ShellRules

_CHAIN_TOKENS = {";", "&&", "||", "&"}
_REDIRECT_CHARS = set("><")


@dataclass
class ShellVerdict:
    ok: bool
    rule: str = ""
    reason: str = ""
    command: str = ""


def _scan_substitutions(cmd: str) -> tuple[bool, bool]:
    """Проверяет наличие подстановки команд (`$(...)`, `` `...` ``) и переменных (`$VAR`) вне одиночных кавычек."""
    in_single = False
    escaped = False
    has_subshell = False
    has_env = False
    for i, ch in enumerate(cmd):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_single:
            in_single = True
            continue
        if ch == "'" and in_single:
            in_single = False
            continue
        if in_single:
            continue
        if ch == "`":
            has_subshell = True
        elif ch == "$" and i + 1 < len(cmd):
            nxt = cmd[i + 1]
            if nxt == "(":
                has_subshell = True
            elif nxt.isalpha() or nxt in ("_", "{", "@", "*", "?", "#"):
                has_env = True
        elif ch in ("<", ">") and i + 1 < len(cmd) and cmd[i + 1] == "(":
            has_subshell = True
    return has_subshell, has_env


def check_shell(cmd: str, rules: ShellRules) -> ShellVerdict:
    if not isinstance(cmd, str) or not cmd.strip():
        return ShellVerdict(False, "shell.empty", "Пустая команда оболочки")
    if any(ch in cmd for ch in ("\x00", "\n", "\r")):
        return ShellVerdict(False, "shell.control_char", "Команда содержит перевод строки или нулевой байт")

    has_sub, has_env = _scan_substitutions(cmd)
    if has_sub and not rules.allow_subshells:
        return ShellVerdict(False, "shell.subshell", "Подстановка команд ($(...) или обратные кавычки) запрещена")
    if has_env and not rules.allow_env_expansion:
        return ShellVerdict(False, "shell.env", "Подстановка переменных окружения ($VAR) запрещена")

    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";|&><()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError as err:
        return ShellVerdict(False, "shell.parse", f"Команда не разобрана лексером: {err}")

    if not tokens:
        return ShellVerdict(False, "shell.empty", "Пустая команда оболочки")

    for tok in tokens:
        if tok in _CHAIN_TOKENS and not rules.allow_chaining:
            return ShellVerdict(False, "shell.chaining", f"Объединение команд через «{tok}» запрещено")
        if tok == "|" and not rules.allow_pipes:
            return ShellVerdict(False, "shell.pipe", "Конвейер «|» запрещён политикой")
        if any(ch in _REDIRECT_CHARS for ch in tok) and tok not in ("<(", ">(") and not rules.allow_redirects:
            return ShellVerdict(False, "shell.redirect", f"Перенаправление ввода/вывода «{tok}» запрещено")
        if tok in ("(", ")") and not rules.allow_subshells:
            return ShellVerdict(False, "shell.subshell", "Подоболочка (...) запрещена")

    first = tokens[0]
    if "=" in first and not first.startswith("-"):
        return ShellVerdict(False, "shell.env_prefix", f"Передача переменной окружения «{first}» перед командой запрещена")

    normalized = first.replace("\\", "/")
    if "/" in normalized and not rules.allow_path_executables:
        return ShellVerdict(False, "shell.path_executable",
                            f"Запуск по пути «{first}» запрещён, допустимо только имя команды")

    exe = PurePosixPath(normalized).name.lower()
    deny = {c.lower() for c in rules.deny_commands}
    if exe in deny:
        return ShellVerdict(False, "shell.command_denied", f"Команда «{exe}» запрещена политикой", exe)
    if rules.allow_commands is not None:
        allow = {c.lower() for c in rules.allow_commands}
        if exe not in allow:
            return ShellVerdict(False, "shell.command_not_allowed",
                                f"Команда «{exe}» не входит в список разрешённых", exe)

    deny_flags = {f.lower() for f in rules.deny_flags.get(exe, [])}
    if deny_flags:
        for arg in tokens[1:]:
            low_arg = arg.lower()
            flag_name = low_arg.split("=", 1)[0]
            if low_arg in deny_flags or flag_name in deny_flags:
                return ShellVerdict(False, "shell.flag_denied",
                                    f"Флаг «{arg}» запрещён для команды «{exe}»", exe)

    return ShellVerdict(True, command=exe)
