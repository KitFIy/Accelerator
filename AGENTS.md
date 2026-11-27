# Axisec — инструкции проекта

Axisec — детерминированный шлюз (Policy Enforcement Point) между ИИ-агентом и корпоративной инфраструктурой. Перехватывает вызовы инструментов на двух точках контроля (ответ LLM `/v1/chat/completions` и прокси MCP `/mcp/{server}`), проверяет SQL по AST (`sqlglot`), аргументы по схеме (`Pydantic`), фильтрует секреты и ПДн (DLP), ведёт журнал аудита и включает полигон Red Team.

## Стек и структура

- Язык и runtime: Python 3.12+ (локальное окружение `.venv`), FastAPI, Uvicorn, httpx, Pydantic v2, PyYAML, sqlglot.
- Основные модули:
  - `axisec/policy.py`, `axisec/engine.py`, `axisec/guards/` — модель политики, движок решений, AST-валидатор SQL, проверка аргументов, DLP.
  - `axisec/gateway/` — HTTP-приложение (`app.py`), две точки контроля (`proxy.py`), адаптеры провайдеров.
  - `axisec/redteam/` — сценарии атак и рабочих задач (`scenarios.yaml`), корпус прямых вызовов (`corpus.yaml`), раннер (`runner.py`).
  - `axisec/demo/` — демо-мир «Ромашка» (`world.py`), имитатор модели (`mock_llm.py`), MCP-сервер (`mcp_server.py`), цикл агента (`agent.py`).
  - `axisec/dashboard/index.html` — встроенный веб-дашборд.
  - `policies/` — YAML-политики (по умолчанию `policies/crm_agent.yaml`).
  - `deck/`, `deliverables/`, `source/`, `docs/` — скрипты сборки, презентации/паспорт, исходники команды, фактчек и результаты.

## Команды запуска и проверки

```powershell
# Активация / запуск из .venv
.venv\Scripts\python.exe -m axisec                  # http://127.0.0.1:8080
.venv\Scripts\python.exe -m pytest -q               # автотесты
.venv\Scripts\python.exe bench/latency.py           # замеры задержки -> bench/results.json
.venv\Scripts\python.exe deck/build_decks.py        # пересборка презентаций
.venv\Scripts\python.exe deck/build_passport.py     # пересборка паспорта
```

Docker-сборка (учёт лимитов Docker Hub):
```bash
docker build --build-arg PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim -t axisec .
```

## Правила и договорённости

- **Ветвление:** основная ветка `ccr-bca1b7b0-rcgzee` (она же production на Vercel) не трогается напрямую. Вся разработка ведётся в отдельной ветке (сейчас `feat/demo-day-and-v02`) до явного утверждения и мерджа пользователем.
- **Только чтение:** `source/` — оригиналы команды, не изменять.
- **Происхождение цифр:** все измеренные цифры сначала фиксируются в `docs/02_mvp_results.md`, внешние факты — в `docs/01_research_factcheck.md`, и только затем переносятся на слайды.
- **Канонические роли команды** (по `source/passport_original.docx`):
  - Андросик Стефан Витальевич — Team Lead / Архитектор ИБ (архитектура, политики, пилоты).
  - Малюгин Егор Андреевич — Backend-разработчик / Ядро (FastAPI/uvloop, AST SQL на sqlglot, Pydantic v2, Docker).
  - Мотов Александр Олегович — Red Team / Frontend (атаки по OWASP, дашборд инцидентов, отчёты аудита).
- **Ущерб и корпус:** ущерб на стенде оценивается по состоянию `World.harms`, а не по логам шлюза. Новая атака в `scenarios.yaml` должна наносить ущерб без шлюза (`test_red_team_suite`); новое правило движка получает в `corpus.yaml` и блокируемые, и легитимные примеры.
- **Безопасность деплоя и секреты:** в `.vercelignore` исключены `source/`, `deliverables/`, `docs/`, `deck/`, `tests/`, `bench/`. Секреты и API-ключи никогда не попадают в код, конфиги и коммиты.
