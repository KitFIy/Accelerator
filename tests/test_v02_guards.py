"""Тесты новых гардов v0.2: корпуса PostgreSQL, MySQL, shell, path и потоковый DLP."""

from pathlib import Path

import pytest
import yaml

from axisec.engine import PolicyEngine
from axisec.guards.dlp import StreamMasker
from axisec.guards.path import check_path
from axisec.guards.shell import check_shell
from axisec.guards.sql import check_sql
from axisec.policy import PathRules, Policy, ShellRules, SqlRules

CORPORA_DIR = Path(__file__).resolve().parents[1] / "axisec" / "redteam" / "corpora"


def _load(name: str) -> list[dict]:
    return yaml.safe_load((CORPORA_DIR / name).read_text(encoding="utf-8"))


PG_CORPUS = _load("postgres.yaml")
MYSQL_CORPUS = _load("mysql.yaml")
SHELL_CORPUS = _load("shell.yaml")
PATH_CORPUS = _load("path.yaml")

PG_RULES = SqlRules(
    dialect="postgres",
    allow_statements=["select"],
    tables_allow=["customers", "orders"],
    columns_deny={"customers": ["passport", "card_number"]},
    max_rows=50,
)
MYSQL_RULES = SqlRules(
    dialect="mysql",
    allow_statements=["select"],
    tables_allow=["customers", "orders"],
    columns_deny={"customers": ["passport", "card_number"]},
    max_rows=50,
)
SHELL_RULES = ShellRules(
    allow_commands=["ls", "cat", "grep", "git", "find", "tar"],
    deny_flags={"find": ["-exec", "-execdir", "-delete"], "tar": ["--checkpoint-action"], "git": ["-c", "--upload-pack"]},
)
PATH_RULES = PathRules(allow_roots=["/app/data"], allow_extensions=[".md", ".txt", ".csv", ".json"])


@pytest.mark.parametrize("case", PG_CORPUS, ids=[c["id"] for c in PG_CORPUS])
def test_postgres_corpus(case: dict) -> None:
    v = check_sql(case["args"]["query"], PG_RULES)
    if case["expect"] == "block":
        assert not v.ok and v.rule and v.reason, f"{case['id']} должен блокироваться"
    else:
        assert v.ok, f"{case['id']} должен проходить: {v.rule} — {v.reason}"


@pytest.mark.parametrize("case", MYSQL_CORPUS, ids=[c["id"] for c in MYSQL_CORPUS])
def test_mysql_corpus(case: dict) -> None:
    v = check_sql(case["args"]["query"], MYSQL_RULES)
    if case["expect"] == "block":
        assert not v.ok and v.rule and v.reason, f"{case['id']} должен блокироваться"
    else:
        assert v.ok, f"{case['id']} должен проходить: {v.rule} — {v.reason}"


@pytest.mark.parametrize("case", SHELL_CORPUS, ids=[c["id"] for c in SHELL_CORPUS])
def test_shell_corpus(case: dict) -> None:
    v = check_shell(case["args"]["cmd"], SHELL_RULES)
    if case["expect"] == "block":
        assert not v.ok and v.rule and v.reason, f"{case['id']} должен блокироваться"
    else:
        assert v.ok, f"{case['id']} должен проходить: {v.rule} — {v.reason}"


@pytest.mark.parametrize("case", PATH_CORPUS, ids=[c["id"] for c in PATH_CORPUS])
def test_path_corpus(case: dict) -> None:
    v = check_path(case["args"]["path"], PATH_RULES)
    if case["expect"] == "block":
        assert not v.ok and v.rule and v.reason, f"{case['id']} должен блокироваться"
    else:
        assert v.ok, f"{case['id']} должен проходить: {v.rule} — {v.reason}"


def test_engine_evaluates_shell_and_path_rules():
    policy = Policy.model_validate({
        "tools": {
            "run_cmd": {"args": {"cmd": {"type": "shell", "required": True, "shell": {"allow_commands": ["git", "ls"]}}}},
            "read_file": {"args": {"path": {"type": "path", "required": True, "path": {"allow_roots": ["/srv/docs"]}}}},
        }
    })
    eng = PolicyEngine(policy)
    assert eng.evaluate("run_cmd", {"cmd": "git status"}).action == "allow"
    b = eng.evaluate("run_cmd", {"cmd": "git status; rm -rf /"})
    assert b.blocked and b.rule == "shell.chaining" and "ASI05" in " ".join(b.owasp)
    assert eng.evaluate("read_file", {"path": "/srv/docs/a.md"}).action == "allow"
    p = eng.evaluate("read_file", {"path": "/srv/docs/../.env"})
    assert p.blocked and p.rule == "path.traversal"


def test_stream_dlp_masks_secret_split_across_chunks():
    masker = StreamMasker(["api_key"], tail_keep=48)
    chunks = ["Ответ: ключ ", "sk-live-4f9a8b", "7c6d5e4f3a2b1c", "0d9e8f7a6b5c — не показывайте его."]
    emitted = "".join(masker.feed(c) for c in chunks) + masker.flush()
    assert "sk-live" not in emitted
    assert "[API_КЛЮЧ_СКРЫТ]" in emitted
    assert "api_key" in masker.detected


def test_extra_corpora_runner_summary():
    from axisec.redteam.runner import evaluate_extra_corpora

    rep = evaluate_extra_corpora()
    assert set(rep) == {"postgres", "mysql", "shell", "path"}
    for name, stats in rep.items():
        assert stats["attacks"] > 0 and stats["benign"] > 0, name
        assert stats["blocked"] == stats["attacks"], name
        assert stats["passed"] == stats["benign"], name
