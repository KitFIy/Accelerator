"""Адаптеры LLM-провайдеров: OpenAI-совместимые API, GigaChat (OAuth2 + functions) и Yandex AI Studio."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_GIGACHAT_UPSTREAM = "https://api.giga.chat/v1"
DEFAULT_GIGACHAT_OAUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
DEFAULT_GIGACHAT_SCOPE = "GIGACHAT_API_PERS"
DEFAULT_YANDEX_UPSTREAM = "https://llm.api.cloud.yandex.net/v1"


class ProviderError(Exception):
    """Ошибка авторизации или протокола при обращении к провайдеру LLM."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def detect_provider(upstream: str, explicit: str = "") -> str:
    """Определяет провайдера по явному имени или URL апстрима."""
    kind = (explicit or os.getenv("AXISEC_LLM_PROVIDER", "")).strip().lower()
    if kind and kind != "auto":
        return kind
    low = (upstream or "").strip().lower()
    if not low or low == "demo":
        return "demo"
    if "giga.chat" in low or "devices.sberbank.ru" in low:
        return "gigachat"
    if "yandex.net" in low:
        return "yandex"
    return "openai"


def resolve_upstream(provider: str, upstream: str) -> str:
    """Подставляет стандартный адрес API для выбранного провайдера, если адрес не задан."""
    if upstream and upstream != "demo":
        return upstream
    if provider == "gigachat":
        return DEFAULT_GIGACHAT_UPSTREAM
    if provider == "yandex":
        return DEFAULT_YANDEX_UPSTREAM
    return upstream or "demo"


def _chat_url(upstream: str) -> str:
    base = upstream.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


@dataclass
class GigaChatOAuth:
    """Кэширует OAuth2-токен GigaChat и обновляет его до истечения срока действия."""

    auth_key: str
    oauth_url: str = DEFAULT_GIGACHAT_OAUTH_URL
    scope: str = DEFAULT_GIGACHAT_SCOPE
    _token: str = ""
    _expires_at: float = 0.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def get_token(self, http: httpx.AsyncClient) -> str:
        now = time.time()
        if self._token and now < self._expires_at - 60:
            return self._token
        async with self._lock:
            now = time.time()
            if self._token and now < self._expires_at - 60:
                return self._token
            auth = self.auth_key.strip()
            if not auth.lower().startswith("basic "):
                auth = f"Basic {auth}"
            r = await http.post(
                self.oauth_url,
                data={"scope": self.scope},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "RqUID": str(uuid.uuid4()),
                    "Authorization": auth,
                },
            )
            if r.status_code >= 400:
                raise ProviderError(f"GigaChat OAuth вернул {r.status_code}: {r.text[:200]}")
            try:
                data = r.json()
            except ValueError as err:
                raise ProviderError("GigaChat OAuth вернул не JSON") from err
            token = data.get("access_token")
            if not token:
                raise ProviderError("В ответе GigaChat OAuth нет access_token")
            exp = data.get("expires_at")
            if isinstance(exp, (int, float)):
                # GigaChat возвращает expires_at в миллисекундах
                self._expires_at = exp / 1000.0 if exp > 1e12 else float(exp)
            else:
                self._expires_at = now + float(data.get("expires_in", 1800))
            self._token = str(token)
            return self._token

    def invalidate(self) -> None:
        self._token = ""
        self._expires_at = 0.0


def _parse_args_dict(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw or "{}")
            return val if isinstance(val, dict) else {"value": val}
        except ValueError:
            return {}
    return {}


def _as_json_string(content: Any) -> str:
    if isinstance(content, str):
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
                return stripped
            except ValueError:
                pass
        return json.dumps({"result": content}, ensure_ascii=False)
    return json.dumps(content if content is not None else {}, ensure_ascii=False)


def openai_to_gigachat_request(body: dict) -> tuple[dict, bool]:
    """Преобразует OpenAI Chat Completions (tools / role=tool) в формат GigaChat (functions / role=function).

    Если клиент уже отправил нативный формат GigaChat (`functions`), запрос не переписывается.
    Возвращает `(новый_запрос, нужно_ли_преобразовать_function_call_обратно_в_tool_calls)`.
    """
    if "functions" in body or "tools" not in body:
        return dict(body), False

    out = dict(body)
    tools = out.pop("tools", None) or []
    tool_choice = out.pop("tool_choice", None)
    out.pop("parallel_tool_calls", None)
    out.pop("stream_options", None)

    functions = [
        t["function"]
        for t in tools
        if isinstance(t, dict) and t.get("type") == "function" and isinstance(t.get("function"), dict)
    ]
    if functions:
        out["functions"] = functions
        if tool_choice == "none":
            out["function_call"] = "none"
        elif isinstance(tool_choice, dict) and isinstance(tool_choice.get("function"), dict):
            out["function_call"] = {"name": tool_choice["function"].get("name", "")}
        else:
            out.setdefault("function_call", "auto")

    call_names: dict[str, str] = {}
    converted_messages: list[dict] = []
    for m in out.get("messages") or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            calls = m["tool_calls"]
            for tc in calls:
                fn = tc.get("function") or {}
                if tc.get("id") and fn.get("name"):
                    call_names[tc["id"]] = fn["name"]
            first = calls[0]
            fn = first.get("function") or {}
            msg: dict[str, Any] = {
                "role": "assistant",
                "content": m.get("content") or "",
                "function_call": {
                    "name": fn.get("name", ""),
                    "arguments": _parse_args_dict(fn.get("arguments")),
                },
            }
            if m.get("functions_state_id"):
                msg["functions_state_id"] = m["functions_state_id"]
            converted_messages.append(msg)
        elif role == "tool":
            call_id = m.get("tool_call_id", "")
            name = m.get("name") or call_names.get(call_id, "tool")
            converted_messages.append({
                "role": "function",
                "name": name,
                "content": _as_json_string(m.get("content", "")),
            })
        else:
            converted_messages.append(dict(m))
    out["messages"] = converted_messages
    return out, True


def gigachat_to_openai_response(resp: dict) -> dict:
    """Конвертирует оставшийся `function_call` из ответа GigaChat в OpenAI `tool_calls`."""
    for choice in resp.get("choices") or []:
        msg = choice.get("message")
        if not isinstance(msg, dict):
            continue
        fc = msg.pop("function_call", None)
        if isinstance(fc, dict):
            args = fc.get("arguments")
            arg_str = args if isinstance(args, str) else json.dumps(args if args is not None else {}, ensure_ascii=False)
            msg["tool_calls"] = [{
                "id": "call_" + uuid.uuid4().hex[:12],
                "type": "function",
                "function": {"name": fc.get("name", ""), "arguments": arg_str},
            }]
            if choice.get("finish_reason") in (None, "function_call", "stop"):
                choice["finish_reason"] = "tool_calls"
    return resp


class ProviderAdapter:
    """Единый клиент для отправки chat/completions на OpenAI, GigaChat или Yandex AI Studio."""

    def __init__(
        self,
        upstream: str,
        *,
        provider: str = "",
        api_key: str = "",
        gigachat_auth_key: str = "",
        gigachat_oauth_url: str = "",
        gigachat_scope: str = "",
        yandex_folder_id: str = "",
        yandex_auth_scheme: str = "",
    ):
        self.provider = detect_provider(upstream, provider)
        self.upstream = resolve_upstream(self.provider, upstream)
        self.api_key = api_key
        self.yandex_folder_id = yandex_folder_id or os.getenv("AXISEC_YANDEX_FOLDER_ID", "")
        self.yandex_auth_scheme = yandex_auth_scheme or os.getenv("AXISEC_YANDEX_AUTH_SCHEME", "")
        auth_key = gigachat_auth_key or os.getenv("AXISEC_GIGACHAT_AUTH_KEY", "")
        self.gigachat_oauth: GigaChatOAuth | None = None
        if self.provider == "gigachat" and auth_key:
            self.gigachat_oauth = GigaChatOAuth(
                auth_key=auth_key,
                oauth_url=gigachat_oauth_url or os.getenv("AXISEC_GIGACHAT_OAUTH_URL", DEFAULT_GIGACHAT_OAUTH_URL),
                scope=gigachat_scope or os.getenv("AXISEC_GIGACHAT_SCOPE", DEFAULT_GIGACHAT_SCOPE),
            )

    def _auth_header_sync(self, client_auth: str) -> str:
        if self.api_key:
            key = self.api_key.strip()
            if key.lower().startswith(("bearer ", "api-key ", "basic ")):
                return key
            if self.provider == "yandex":
                scheme = self.yandex_auth_scheme.strip()
                if not scheme:
                    scheme = "Bearer" if key.startswith("t1.") else "Api-Key"
                return f"{scheme} {key}"
            return f"Bearer {key}"
        return client_auth

    async def prepare_request(self, body: dict, client_auth: str, http: httpx.AsyncClient) -> tuple[str, dict, dict, bool]:
        """Возвращает `(url, payload, headers, normalize_gigachat_fc)`."""
        headers: dict[str, str] = {"accept": "application/json"}
        normalize_fc = False

        if self.provider == "gigachat":
            payload, normalize_fc = openai_to_gigachat_request(body)
            if self.gigachat_oauth is not None:
                token = await self.gigachat_oauth.get_token(http)
                headers["authorization"] = f"Bearer {token}"
            else:
                auth = self._auth_header_sync(client_auth)
                if auth:
                    headers["authorization"] = auth
        elif self.provider == "yandex":
            payload = dict(body)
            auth = self._auth_header_sync(client_auth)
            if auth:
                headers["authorization"] = auth
            if self.yandex_folder_id:
                headers["x-folder-id"] = self.yandex_folder_id
        else:
            payload = dict(body)
            auth = self._auth_header_sync(client_auth)
            if auth:
                headers["authorization"] = auth

        return _chat_url(self.upstream), payload, headers, normalize_fc

    async def send_chat(self, body: dict, client_auth: str, http: httpx.AsyncClient) -> tuple[int, dict, bool]:
        url, payload, headers, normalize_fc = await self.prepare_request(body, client_auth, http)
        r = await http.post(url, json=payload, headers=headers)
        if r.status_code == 401 and self.provider == "gigachat" and self.gigachat_oauth is not None:
            # Токен мог быть отозван на стороне сервера до срока — обновляем один раз
            self.gigachat_oauth.invalidate()
            headers["authorization"] = f"Bearer {await self.gigachat_oauth.get_token(http)}"
            r = await http.post(url, json=payload, headers=headers)
        try:
            return r.status_code, r.json(), normalize_fc
        except ValueError:
            return 502, {"error": {"message": "Вышестоящая модель вернула не JSON", "type": "axisec_upstream"}}, normalize_fc
