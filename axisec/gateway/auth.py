"""Проверка токенов для API дашборда (admin) и шлюза агентов (gateway + RBAC)."""

from __future__ import annotations

import hmac
import json
import os


def _extract_bearer(header: str) -> str:
    h = header.strip()
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return h


def load_gateway_tokens(raw: str | None = None) -> dict[str, str]:
    """Возвращает отображение `{токен: роль}`. Пустой словарь — авторизация шлюза отключена."""
    spec = raw if raw is not None else os.getenv("AXISEC_GATEWAY_TOKENS", "")
    single = os.getenv("AXISEC_GATEWAY_TOKEN", "").strip()
    tokens: dict[str, str] = {}
    if spec.strip():
        text = spec.strip()
        if text.startswith("{"):
            data = json.loads(text)
            if isinstance(data, dict):
                tokens.update({str(k): str(v or "") for k, v in data.items() if str(k).strip()})
        else:
            for item in text.split(","):
                item = item.strip()
                if not item:
                    continue
                if ":" in item:
                    tok, role = item.split(":", 1)
                    tokens[tok.strip()] = role.strip()
                else:
                    tokens[item] = ""
    if single:
        tokens.setdefault(single, "")
    return tokens


class AuthConfig:
    def __init__(self, admin_token: str | None = None, gateway_tokens: dict[str, str] | None = None):
        self.admin_token = (admin_token if admin_token is not None else os.getenv("AXISEC_ADMIN_TOKEN", "")).strip()
        self.gateway_tokens = gateway_tokens if gateway_tokens is not None else load_gateway_tokens()

    @property
    def admin_enabled(self) -> bool:
        return bool(self.admin_token)

    @property
    def gateway_enabled(self) -> bool:
        return bool(self.gateway_tokens)

    def check_admin(self, headers: dict[str, str], query_token: str = "") -> bool:
        if not self.admin_token:
            return True
        candidate = (
            headers.get("x-axisec-admin-token")
            or _extract_bearer(headers.get("authorization", ""))
            or query_token
        ).strip()
        return bool(candidate) and hmac.compare_digest(candidate, self.admin_token)

    def check_gateway(self, headers: dict[str, str]) -> tuple[bool, str]:
        """Возвращает `(разрешено, привязанная_роль)`."""
        if not self.gateway_tokens:
            return True, ""
        candidate = (
            headers.get("x-axisec-key")
            or _extract_bearer(headers.get("authorization", ""))
        ).strip()
        if not candidate:
            return False, ""
        for tok, role in self.gateway_tokens.items():
            if hmac.compare_digest(candidate, tok):
                return True, role
        return False, ""
