"""Проверка файловых путей: защита от traversal, скрытых файлов, секретов и выхода за allow_roots."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..policy import PathRules

_ENCODED_TRAVERSAL = re.compile(r"%(?:2e|2f|5c|00)", re.I)
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


@dataclass
class PathVerdict:
    ok: bool
    rule: str = ""
    reason: str = ""
    normalized: str = ""


def check_path(raw: str, rules: PathRules) -> PathVerdict:
    if not isinstance(raw, str) or not raw.strip():
        return PathVerdict(False, "path.empty", "Пустой путь к файлу")
    if any(ord(ch) < 32 for ch in raw):
        return PathVerdict(False, "path.control_char", "Путь содержит управляющие символы")
    if _ENCODED_TRAVERSAL.search(raw):
        return PathVerdict(False, "path.encoded", "Путь содержит URL-кодированные разделители или точки")

    norm_raw = raw.strip().replace("\\", "/")
    if norm_raw.startswith("~"):
        return PathVerdict(False, "path.tilde", "Раскрытие домашнего каталога (~) запрещено")
    if norm_raw.startswith("//"):
        return PathVerdict(False, "path.unc", "Сетевые UNC-пути запрещены")

    raw_parts = [p for p in norm_raw.split("/") if p]
    if ".." in raw_parts:
        return PathVerdict(False, "path.traversal", "Переход вверх по дереву (..) запрещён")

    resolved = posixpath.normpath(norm_raw)
    is_abs = resolved.startswith("/") or bool(_DRIVE_PREFIX.match(resolved))
    if is_abs and not rules.allow_absolute:
        return PathVerdict(False, "path.absolute", "Абсолютные пути запрещены политикой")

    if rules.allow_roots is not None:
        p = PurePosixPath(resolved)
        allowed = False
        for root in rules.allow_roots:
            root_norm = posixpath.normpath(root.strip().replace("\\", "/"))
            rp = PurePosixPath(root_norm)
            if p.is_absolute() != rp.is_absolute():
                continue
            if p == rp or p.is_relative_to(rp):
                allowed = True
                break
        if not allowed:
            return PathVerdict(False, "path.outside_root",
                               f"Путь «{resolved}» выходит за пределы разрешённых каталогов")

    parts = [seg for seg in PurePosixPath(resolved).parts if seg not in ("/", "")]
    deny_names = {n.lower() for n in rules.deny_names}
    for seg in parts:
        low_seg = seg.lower()
        if low_seg in deny_names:
            return PathVerdict(False, "path.denied_name", f"Доступ к «{seg}» запрещён политикой")
        if not rules.allow_hidden and seg.startswith(".") and seg not in (".", ".."):
            return PathVerdict(False, "path.hidden", f"Доступ к скрытому файлу или каталогу «{seg}» запрещён")

    suffix = PurePosixPath(resolved).suffix.lower()
    if suffix and suffix in {e.lower() for e in rules.deny_extensions}:
        return PathVerdict(False, "path.extension_denied", f"Расширение «{suffix}» запрещено политикой")
    if rules.allow_extensions is not None:
        allow_ext = {e.lower() for e in rules.allow_extensions}
        if suffix not in allow_ext:
            return PathVerdict(False, "path.extension_not_allowed",
                               f"Расширение «{suffix or '(нет)'}» не входит в список разрешённых")

    return PathVerdict(True, normalized=resolved)
