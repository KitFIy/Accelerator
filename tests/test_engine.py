"""Тесты движка политик: корпус атак и легитимных вызовов плюс точечные проверки."""

from pathlib import Path

import pytest
import yaml

from axisec.engine import PolicyEngine
from axisec.guards import dlp
from axisec.guards.sql import check_sql
from axisec.policy import SqlRules, load_policy

ROOT = Path(__file__).resolve().parents[1]
CORPUS = yaml.safe_load((ROOT / "axisec/redteam/corpus.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    return PolicyEngine(load_policy(ROOT / "policies/crm_agent.yaml"))


@pytest.mark.parametrize("case", CORPUS, ids=[c["id"] for c in CORPUS])
def test_corpus(engine: PolicyEngine, case: dict) -> None:
    d = engine.evaluate(case["tool"], case["args"])
    if case["expect"] == "block":
        assert d.blocked, f"{case['id']} должен быть заблокирован, но прошёл"
        assert d.rule and d.reason
    else:
        assert not d.blocked, f"{case['id']} должен пройти, заблокирован: {d.rule} — {d.reason}"


def test_corpus_is_big_enough() -> None:
    attacks = [c for c in CORPUS if c["expect"] == "block"]
    benign = [c for c in CORPUS if c["expect"] == "allow"]
    assert len(attacks) >= 90 and len(benign) >= 35
    assert len({c["id"] for c in CORPUS}) == len(CORPUS)


def test_limit_is_rewritten(engine: PolicyEngine) -> None:
    d = engine.evaluate("run_sql", {"query": "SELECT name FROM customers WHERE city = 'Москва'"})
    assert d.action == "modify" and d.new_args["query"].endswith("LIMIT 50")
    d = engine.evaluate("run_sql", {"query": "SELECT name FROM customers LIMIT 100000"})
    assert d.action == "modify" and "100000" not in d.new_args["query"]
    d = engine.evaluate("run_sql", {"query": "SELECT name FROM customers LIMIT 5"})
    assert d.action == "allow"


def test_decision_is_deterministic(engine: PolicyEngine) -> None:
    q = {"query": "DROP TABLE customers"}
    results = {(d.action, d.rule) for d in (engine.evaluate("run_sql", q) for _ in range(200))}
    assert results == {("block", "sql.statement")}


def test_owasp_tags(engine: PolicyEngine) -> None:
    d = engine.evaluate("run_sql", {"query": "DROP TABLE customers"})
    assert any(t.startswith("LLM06") for t in d.owasp) and any(t.startswith("ASI02") for t in d.owasp)
    d = engine.evaluate("run_sql", {"query": "SELECT key FROM api_keys"})
    assert any(t.startswith("LLM02") for t in d.owasp)


def test_postgres_dialect() -> None:
    rules = SqlRules(dialect="postgres", allow_statements=["select"])
    for q in ["COPY t TO PROGRAM 'curl evil'", "SELECT pg_read_file('/etc/passwd')",
              "DO $$ BEGIN EXECUTE 'DROP TABLE t'; END $$", "SELECT * INTO loot FROM t",
              "SET ROLE admin", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
              "SELECT * FROM pg_catalog.pg_shadow", "SELECT * FROM information_schema.tables"]:
        assert not check_sql(q, rules).ok, q
    assert check_sql("SELECT a FROM t WHERE b = 1", rules).ok


def test_dlp_detects_and_masks() -> None:
    text = ("ключ sk-live-4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c, карта 4111 1111 1111 1111, "
            "СНИЛС 112-233-445 95, паспорт 4510 123456, тел. +7 (495) 123-45-67, a@b.example")
    types = {f.type for f in dlp.scan(text)}
    assert {"api_key", "card_number", "snils", "passport_ru", "phone_ru", "email"} <= types
    masked, _ = dlp.mask(text)
    assert "sk-live" not in masked and "4111" not in masked and "[API_КЛЮЧ_СКРЫТ]" in masked


def test_dlp_no_false_positives_on_plain_numbers() -> None:
    assert dlp.scan("Заказ 1001 на сумму 15000 руб. от 12.11.2026, трек 1234567890123456") == []
    assert dlp.scan("СНИЛС 123-456-789 00") == []  # неверная контрольная сумма


def test_response_masking_respects_policy(engine: PolicyEngine) -> None:
    masked, types = engine.scan_text("token=abcd1234efgh5678 и почта ivanov@mail.example")
    assert "abcd1234" not in masked and "ivanov@mail.example" in masked
    assert types == ["secret_assignment"]


def test_tool_visibility(engine: PolicyEngine) -> None:
    assert engine.tool_visible("run_sql")
    assert not engine.tool_visible("delete_customer")
    assert not engine.tool_visible("exec_shell")
