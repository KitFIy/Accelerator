"""DLP: поиск секретов и персональных данных в тексте, маскирование."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int


def _luhn(digits: str) -> bool:
    nums = [int(d) for d in digits]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _snils_ok(digits: str) -> bool:
    if len(digits) != 11:
        return False
    body, control = digits[:9], int(digits[9:])
    s = sum(int(d) * (9 - i) for i, d in enumerate(body))
    expected = s if s < 100 else (0 if s in (100, 101) else (s % 101 if s % 101 < 100 else 0))
    return expected == control


def _only_digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# (тип, регулярное выражение, проверка совпадения или None)
_DETECTORS: list[tuple[str, re.Pattern[str], Callable[[str], bool] | None]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), None),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None),
    ("api_key", re.compile(
        r"\b(?:sk|pk|rk)[-_](?:live|test|proj|prod)?[-_]?[A-Za-z0-9_-]{20,}"
        r"|\bAKIA[0-9A-Z]{16}\b"
        r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
        r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
        r"|\bglpat-[A-Za-z0-9_-]{20,}"
        r"|\bAIza[0-9A-Za-z_-]{30,}"
        r"|\by0_[A-Za-z0-9_-]{30,}"), None),
    ("secret_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|пароль|токен)\b\s*[:=]\s*[\"']?[^\s\"',;]{8,}"), None),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"), None),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: _luhn(_only_digits(m))),
    ("snils", re.compile(r"\b\d{3}-\d{3}-\d{3}[ -]?\d{2}\b"), lambda m: _snils_ok(_only_digits(m))),
    ("passport_ru", re.compile(r"(?i)(?:паспорт\w*|passport)\D{0,20}\d{2}\s?\d{2}\s?\d{6}\b"), None),
    ("phone_ru", re.compile(r"(?<![\w+])(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]?\d{2}[\s-]?\d{2}\b"), None),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
]

DETECTOR_NAMES = [name for name, _, _ in _DETECTORS]
SECRET_TYPES = {"private_key", "jwt", "api_key", "secret_assignment", "bearer_token"}

_LABELS = {
    "private_key": "ЗАКРЫТЫЙ_КЛЮЧ", "jwt": "JWT", "api_key": "API_КЛЮЧ", "secret_assignment": "СЕКРЕТ",
    "bearer_token": "ТОКЕН", "card_number": "НОМЕР_КАРТЫ", "snils": "СНИЛС",
    "passport_ru": "ПАСПОРТ", "phone_ru": "ТЕЛЕФОН", "email": "EMAIL",
}


def scan(text: str, detectors: list[str] | None = None) -> list[Finding]:
    """Возвращает непересекающиеся находки, слева направо."""
    if not text:
        return []
    found: list[Finding] = []
    for name, rx, check in _DETECTORS:
        if detectors is not None and name not in detectors:
            continue
        for m in rx.finditer(text):
            if check is None or check(m.group(0)):
                found.append(Finding(name, m.start(), m.end()))
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    result: list[Finding] = []
    last_end = -1
    for f in found:
        if f.start >= last_end:
            result.append(f)
            last_end = f.end
    return result


def mask(text: str, detectors: list[str] | None = None) -> tuple[str, list[Finding]]:
    findings = scan(text, detectors)
    if not findings:
        return text, findings
    out, pos = [], 0
    for f in findings:
        out.append(text[pos:f.start])
        out.append(f"[{_LABELS.get(f.type, f.type.upper())}_СКРЫТ]")
        pos = f.end
    out.append(text[pos:])
    return "".join(out), findings


class StreamMasker:
    """Потоковый DLP-фильтр со скользящим буфером для защиты секретов на границе чанков SSE."""

    def __init__(self, detectors: list[str] | None = None, tail_keep: int = 128):
        self.detectors = detectors
        self.tail_keep = tail_keep
        self._buf = ""
        self.detected: set[str] = set()

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        self._buf += chunk
        if len(self._buf) <= self.tail_keep:
            return ""
        masked, findings = mask(self._buf, self.detectors)
        self.detected.update(f.type for f in findings)
        cut = len(masked) - self.tail_keep
        # Не режем прямо внутри [LABEL_СКРЫТ] и по возможности режем на пробеле/переносе строки
        if "[" in masked[max(0, cut - 30):cut] and "]" in masked[cut:min(len(masked), cut + 30)]:
            cut = masked.index("]", cut) + 1
        out, self._buf = masked[:cut], masked[cut:]
        return out

    def flush(self) -> str:
        if not self._buf:
            return ""
        masked, findings = mask(self._buf, self.detectors)
        self.detected.update(f.type for f in findings)
        self._buf = ""
        return masked
