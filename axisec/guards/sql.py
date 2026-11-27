"""Проверка SQL по синтаксическому дереву (AST), а не по тексту.

Запрос разбирается парсером sqlglot. Решение принимается по типам узлов
дерева, поэтому регистр, комментарии, переносы строк и прочие текстовые
уловки на результат не влияют. Всё, что не разобрано или не разрешено
явно, блокируется (fail-closed).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from ..policy import SqlRules

logging.getLogger("sqlglot").setLevel(logging.ERROR)

# Класс узла дерева -> вид операции. Порядок важен: первое совпадение.
_KINDS: list[tuple[type, str]] = [
    (exp.Select, "select"), (exp.SetOperation, "select"),
    (exp.Insert, "insert"), (exp.Update, "update"), (exp.Delete, "delete"), (exp.Merge, "merge"),
    (exp.Drop, "drop"), (exp.TruncateTable, "truncate"), (exp.Alter, "alter"), (exp.Create, "create"),
    (exp.Pragma, "pragma"), (exp.Attach, "attach"), (exp.Detach, "detach"), (exp.Grant, "grant"),
    (exp.Copy, "copy"), (exp.Into, "select_into"), (exp.Set, "set"), (exp.Use, "use"),
    (exp.Transaction, "transaction"), (exp.Commit, "transaction"), (exp.Rollback, "transaction"),
    (exp.Command, "command"),
]
_NESTED = tuple(cls for cls, kind in _KINDS if kind != "select")
_SYSTEM_SCHEMAS = {"information_schema", "pg_catalog", "sys", "mysql", "performance_schema", "sqlite_temp_master"}

_RU = {
    "select": "чтение (SELECT)", "insert": "вставка (INSERT)", "update": "изменение (UPDATE)",
    "delete": "удаление строк (DELETE)", "merge": "слияние (MERGE)", "drop": "удаление объекта (DROP)",
    "truncate": "очистка таблицы (TRUNCATE)", "alter": "изменение схемы (ALTER)",
    "create": "создание объекта (CREATE)", "pragma": "служебная команда (PRAGMA)",
    "attach": "подключение базы (ATTACH)", "detach": "отключение базы (DETACH)",
    "grant": "выдача прав (GRANT)", "copy": "выгрузка (COPY)", "select_into": "SELECT INTO",
    "set": "смена параметров (SET)", "use": "смена базы (USE)", "transaction": "управление транзакцией",
    "command": "нераспознанная команда", "upsert": "перезапись строк (INSERT OR REPLACE / ON CONFLICT)",
}


@dataclass
class SqlVerdict:
    ok: bool
    rule: str = ""
    reason: str = ""
    kinds: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    new_sql: str | None = None


def _kind(node: exp.Expression) -> str:
    if isinstance(node, exp.Insert):
        # INSERT OR REPLACE и ON CONFLICT DO UPDATE перезаписывают существующие строки
        if str(node.args.get("alternative") or "").upper() == "REPLACE" or node.args.get("conflict"):
            return "upsert"
    for cls, kind in _KINDS:
        if isinstance(node, cls):
            return kind
    return "other:" + type(node).__name__.lower()


def _is_tautology(e: exp.Expression | None) -> bool:
    """Условие, истинное для любой строки: WHERE 1=1, WHERE true, ... OR 1=1."""
    if e is None:
        return False
    if isinstance(e, exp.Paren):
        return _is_tautology(e.this)
    if isinstance(e, exp.Boolean):
        return bool(e.this)
    if isinstance(e, exp.Or):
        return _is_tautology(e.this) or _is_tautology(e.expression)
    if isinstance(e, exp.And):
        return _is_tautology(e.this) and _is_tautology(e.expression)
    if isinstance(e, (exp.EQ, exp.NEQ)):
        left, right = e.this, e.expression
        if isinstance(left, exp.Literal) and isinstance(right, exp.Literal):
            same = left.this == right.this and left.is_string == right.is_string
            return same if isinstance(e, exp.EQ) else not same
        if isinstance(e, exp.EQ) and isinstance(left, exp.Column) and left == right:
            return True
    return False


def check_sql(sql: str, rules: SqlRules) -> SqlVerdict:
    if not isinstance(sql, str) or not sql.strip():
        return SqlVerdict(False, "sql.empty", "Пустой SQL-запрос")
    try:
        statements = [s for s in sqlglot.parse(sql, read=rules.dialect) if s is not None]
    except Exception as err:  # noqa: BLE001 — любой сбой разбора = отказ
        return SqlVerdict(False, "sql.parse", f"SQL не разобран парсером, отклонён: {str(err)[:120]}")
    if not statements:
        return SqlVerdict(False, "sql.empty", "Пустой SQL-запрос")
    if len(statements) > rules.max_statements:
        return SqlVerdict(False, "sql.stacked",
                          f"Несколько команд в одном запросе ({len(statements)}), разрешено {rules.max_statements}")

    allow = set(rules.allow_statements)
    kinds: list[str] = []
    tables: list[str] = []
    new_sql_parts: list[str] = []
    rewritten = False

    for stmt in statements:
        while isinstance(stmt, (exp.Subquery, exp.Paren)) and stmt.this is not None:
            stmt = stmt.this
        top = _kind(stmt)
        found = {top} | {_kind(n) for n in stmt.find_all(*_NESTED)}
        kinds.extend(sorted(found))
        for k in sorted(found):
            if k not in allow:
                return SqlVerdict(False, "sql.statement",
                                  f"Операция запрещена политикой: {_RU.get(k, k)}", kinds, tables)

        # --- таблицы ---
        cte_names = {c.alias.lower() for c in stmt.find_all(exp.CTE) if c.alias}
        alias_map: dict[str, str] = {}
        real_tables: list[str] = []
        for t in stmt.find_all(exp.Table):
            name, schema = (t.name or "").lower(), (t.db or "").lower()
            if not name:
                continue
            if name in cte_names and not schema:
                continue
            real_tables.append(name)
            alias_map[(t.alias or name).lower()] = name
            if rules.deny_system_catalogs and (name.startswith(("sqlite_", "pg_")) or schema in _SYSTEM_SCHEMAS):
                return SqlVerdict(False, "sql.system_catalog",
                                  f"Обращение к системному каталогу «{name}» запрещено", kinds, real_tables)
            if name in {x.lower() for x in rules.tables_deny}:
                return SqlVerdict(False, "sql.table_denied",
                                  f"Таблица «{name}» закрыта политикой", kinds, real_tables)
            if rules.tables_allow is not None and name not in {x.lower() for x in rules.tables_allow}:
                return SqlVerdict(False, "sql.table_not_allowed",
                                  f"Таблица «{name}» не входит в список разрешённых", kinds, real_tables)
        tables.extend(real_tables)

        # --- функции ---
        deny_fn = {f.lower() for f in rules.deny_functions}
        for f in stmt.find_all(exp.Func):
            fname = (f.name if isinstance(f, exp.Anonymous) else f.sql_name()).lower()
            if fname in deny_fn or fname.startswith(tuple(rules.deny_function_prefixes)):
                return SqlVerdict(False, "sql.function",
                                  f"Вызов функции «{fname}» запрещён", kinds, tables)

        # --- столбцы ---
        cols_deny = {t.lower(): {c.lower() for c in cs} for t, cs in rules.columns_deny.items()}
        if cols_deny:
            for c in stmt.find_all(exp.Column):
                if isinstance(c.this, exp.Star):
                    continue
                col, qual = c.name.lower(), (c.table or "").lower()
                owners = [alias_map.get(qual, qual)] if qual else real_tables
                for owner in owners:
                    if col in cols_deny.get(owner, ()):
                        return SqlVerdict(False, "sql.column_denied",
                                          f"Столбец «{owner}.{col}» закрыт политикой", kinds, tables)
            for star in stmt.find_all(exp.Star):
                if isinstance(star.parent, exp.Count):
                    continue
                qual = ""
                if isinstance(star.parent, exp.Column):
                    qual = (star.parent.table or "").lower()
                owners = [alias_map.get(qual, qual)] if qual else real_tables
                for owner in owners:
                    if cols_deny.get(owner):
                        return SqlVerdict(False, "sql.star",
                                          f"SELECT * раскрывает закрытые столбцы таблицы «{owner}», "
                                          "перечислите нужные столбцы явно", kinds, tables)
            for ins in stmt.find_all(exp.Insert):
                if isinstance(ins.this, exp.Schema) and isinstance(ins.this.this, exp.Table):
                    owner = ins.this.this.name.lower()
                    for ident in ins.this.expressions:
                        if ident.name.lower() in cols_deny.get(owner, ()):
                            return SqlVerdict(False, "sql.column_denied",
                                              f"Столбец «{owner}.{ident.name.lower()}» закрыт политикой",
                                              kinds, tables)

        # --- WHERE обязателен и не должен быть тождеством ---
        for node in stmt.find_all(exp.Update, exp.Delete):
            k = _kind(node)
            where = node.args.get("where")
            if k in rules.require_where and where is None:
                return SqlVerdict(False, "sql.where_required",
                                  f"{_RU[k]} без WHERE затронет все строки таблицы", kinds, tables)
            if rules.deny_tautology and where is not None and _is_tautology(where.this):
                return SqlVerdict(False, "sql.tautology",
                                  f"Условие WHERE всегда истинно: {_RU[k]} затронет все строки", kinds, tables)

        # --- ограничение размера выборки ---
        if rules.max_rows is not None and top == "select" and isinstance(stmt, exp.Query):
            limit = stmt.args.get("limit")
            current = None
            if limit is not None and isinstance(limit.expression, exp.Literal) and not limit.expression.is_string:
                try:
                    current = int(limit.expression.this)
                except ValueError:
                    current = None
            if current is None or current > rules.max_rows:
                if rules.limit_mode == "block":
                    return SqlVerdict(False, "sql.limit",
                                      f"Выборка без ограничения: нужен LIMIT не больше {rules.max_rows}",
                                      kinds, tables)
                stmt = stmt.limit(rules.max_rows)
                rewritten = True
        if rewritten:
            new_sql_parts.append(stmt.sql(dialect=rules.dialect))

    return SqlVerdict(True, "sql.limit" if rewritten else "", "", kinds, tables,
                      "; ".join(new_sql_parts) if rewritten else None)
