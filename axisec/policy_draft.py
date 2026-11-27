"""Автоматическая генерация черновика YAML-политики по описанию инструментов (MCP tools/list или OpenAI tools)."""

from __future__ import annotations

from typing import Any

import yaml

_DANGEROUS_TOOL_HINTS = ("delete", "drop", "exec", "shell", "cmd", "terminal", "admin", "sudo", "destroy", "wipe")


def _normalize_tools(raw_tools: list[dict]) -> list[dict]:
    out: list[dict] = []
    for t in raw_tools:
        if not isinstance(t, dict):
            continue
        if t.get("type") == "function" and isinstance(t.get("function"), dict):
            fn = t["function"]
            out.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "inputSchema": fn.get("parameters") or {},
            })
        elif t.get("name"):
            out.append({
                "name": t["name"],
                "description": t.get("description", ""),
                "inputSchema": t.get("inputSchema") or t.get("parameters") or {},
            })
    return out


def _infer_arg_rule(name: str, prop: dict, required: bool, observed_vals: list[Any]) -> dict:
    low = name.lower()
    schema_type = prop.get("type", "string")
    if isinstance(schema_type, list):
        schema_type = next((x for x in schema_type if x != "null"), "string")

    rule: dict[str, Any] = {}
    if required:
        rule["required"] = True

    if any(k in low for k in ("sql", "query")):
        rule["type"] = "sql"
        rule["max_length"] = 4000
        sql_cfg: dict[str, Any] = {
            "dialect": "sqlite",
            "allow_statements": ["select"],
            "require_where": ["update", "delete"],
            "deny_tautology": True,
            "max_rows": 50,
        }
        if observed_vals:
            tables = sorted({str(t) for v in observed_vals if isinstance(v, str) for t in _guess_tables(v)})
            if tables:
                sql_cfg["tables_allow"] = tables
        rule["sql"] = sql_cfg
        return rule

    if any(k in low for k in ("cmd", "command", "shell", "script")):
        rule["type"] = "shell"
        rule["max_length"] = 500
        rule["shell"] = {"allow_commands": []}  # fail-closed: владелец должен явно вписать разрешённые команды
        return rule

    if any(k in low for k in ("path", "file", "filename", "filepath")):
        rule["type"] = "path"
        rule["max_length"] = 300
        rule["path"] = {"allow_roots": ["/app/data"]}
        return rule

    if any(k in low for k in ("url", "uri", "endpoint", "webhook")):
        rule["type"] = "url"
        rule["max_length"] = 500
        rule["allow_schemes"] = ["https"]
        rule["dlp"] = "block"
        return rule

    if any(k in low for k in ("email", "mail", "recipient")):
        rule["type"] = "email"
        return rule

    if schema_type in ("integer", "number", "boolean", "array", "object", "string"):
        rule["type"] = schema_type
    else:
        rule["type"] = "string"

    if "enum" in prop and isinstance(prop["enum"], list):
        rule["enum"] = prop["enum"]
    if schema_type in ("integer", "number"):
        if "minimum" in prop:
            rule["min"] = prop["minimum"]
        elif any(k in low for k in ("amount", "sum", "price", "limit", "id")):
            rule["min"] = 0
        if "maximum" in prop:
            rule["max"] = prop["maximum"]
        elif any(k in low for k in ("amount", "sum", "price")):
            nums = [v for v in observed_vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if nums:
                rule["max"] = max(nums)
    if rule["type"] == "string":
        rule["max_length"] = prop.get("maxLength", 2000 if any(k in low for k in ("body", "text", "msg", "content")) else 300)
        if "pattern" in prop:
            rule["pattern"] = prop["pattern"]
        if any(k in low for k in ("body", "message", "text", "content", "payload")):
            rule["dlp"] = "block"
    return rule


def _guess_tables(sql_text: str) -> list[str]:
    try:
        import sqlglot
        from sqlglot import exp

        tables: list[str] = []
        for stmt in sqlglot.parse(sql_text):
            if stmt is None:
                continue
            for t in stmt.find_all(exp.Table):
                if t.name:
                    tables.append(t.name.lower())
        return tables
    except Exception:
        return []


def generate_policy_draft(
    raw_tools: list[dict],
    *,
    name: str = "generated-draft",
    mode: str = "observe",
    audit_events: list[dict] | None = None,
) -> dict[str, Any]:
    """Строит черновик политики (dict + YAML-текст) по списку инструментов и истории наблюдений."""
    tools = _normalize_tools(raw_tools)
    observed: dict[str, dict[str, list[Any]]] = {}
    for ev in audit_events or []:
        tname = ev.get("tool", "")
        args = ev.get("args")
        if not tname or not isinstance(args, dict):
            continue
        bucket = observed.setdefault(tname, {})
        for k, v in args.items():
            bucket.setdefault(k, []).append(v)

    tools_cfg: dict[str, Any] = {}
    for t in tools:
        tname = t["name"]
        low = tname.lower()
        desc = t.get("description", "")
        if any(h in low for h in _DANGEROUS_TOOL_HINTS):
            tools_cfg[tname] = {
                "description": desc or "Опасная операция — переведена в deny в черновике",
                "action": "deny",
            }
            continue
        schema = t.get("inputSchema") or {}
        props = schema.get("properties") or {}
        req = set(schema.get("required") or [])
        tool_obs = observed.get(tname, {})
        args_cfg = {
            arg_name: _infer_arg_rule(arg_name, prop or {}, arg_name in req, tool_obs.get(arg_name, []))
            for arg_name, prop in props.items()
        }
        tools_cfg[tname] = {
            "description": desc,
            "action": "allow",
            "args": args_cfg,
        }

    doc = {
        "version": 1,
        "name": name,
        "description": "Автоматически сгенерированный черновик политики (проверьте перед включением enforce)",
        "mode": mode,
        "default_action": "deny",
        "tools": tools_cfg,
        "dlp": {
            "responses": "mask",
            "requests": "mask",
        },
    }
    yaml_text = "# Черновик политики Axisec (режим observe: сначала проверьте срабатывания в журнале)\n" + yaml.safe_dump(
        doc, allow_unicode=True, sort_keys=False
    )
    return {"policy": doc, "yaml": yaml_text, "tools_count": len(tools_cfg)}
