"""Модель политики безопасности. Политика — обычный YAML-файл."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_DENY_FUNCTIONS = [
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer",
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_sleep", "pg_terminate_backend",
    "lo_import", "lo_export", "dblink", "dblink_exec", "copy",
    "load_file", "sleep", "benchmark", "sys_exec", "sys_eval", "xp_cmdshell", "openrowset",
]
DEFAULT_DENY_FUNCTION_PREFIXES = ["pragma_", "pg_", "lo_", "xp_", "sp_"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SqlRules(_Model):
    dialect: str = "sqlite"
    allow_statements: list[str] = Field(default_factory=lambda: ["select"])
    max_statements: int = 1
    tables_allow: list[str] | None = None
    tables_deny: list[str] = Field(default_factory=list)
    columns_deny: dict[str, list[str]] = Field(default_factory=dict)
    require_where: list[str] = Field(default_factory=lambda: ["update", "delete"])
    deny_tautology: bool = True
    max_rows: int | None = None
    limit_mode: Literal["rewrite", "block"] = "rewrite"
    deny_system_catalogs: bool = True
    deny_functions: list[str] = Field(default_factory=lambda: list(DEFAULT_DENY_FUNCTIONS))
    deny_function_prefixes: list[str] = Field(default_factory=lambda: list(DEFAULT_DENY_FUNCTION_PREFIXES))


class ArgRule(_Model):
    type: Literal["string", "integer", "number", "boolean", "url", "email", "sql", "array", "object"] = "string"
    required: bool = False
    enum: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    max_length: int | None = None
    pattern: str | None = None
    allow_hosts: list[str] | None = None
    allow_schemes: list[str] = Field(default_factory=lambda: ["https"])
    dlp: Literal["off", "block", "mask"] = "off"
    dlp_detectors: list[str] | None = None
    sql: SqlRules | None = None


class ToolPolicy(_Model):
    description: str = ""
    action: Literal["allow", "deny"] = "allow"
    args: dict[str, ArgRule] = Field(default_factory=dict)
    allow_extra_args: bool = False


class DlpPolicy(_Model):
    responses: Literal["off", "mask"] = "mask"
    requests: Literal["off", "mask"] = "off"
    detectors: list[str] | None = None


class Policy(_Model):
    version: int = 1
    name: str = "default"
    description: str = ""
    default_action: Literal["deny", "allow"] = "deny"
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    dlp: DlpPolicy = Field(default_factory=DlpPolicy)


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Policy.model_validate(data)
