# Axisec — инструкции для разработки и коллабораторов

Axisec — детерминированный шлюз (Policy Enforcement Point) между ИИ-агентом и корпоративной инфраструктурой. Перехватывает вызовы инструментов на двух точках контроля (ответ LLM `/v1/chat/completions` и прокси MCP `/mcp/{server}`), разбирает SQL по AST (`sqlglot`), shell (`shlex`), файловые пути и аргументы по схемам (`Pydantic v2`), фильтрует секреты/ПДн (DLP, включая потоковый `StreamMasker`), поддерживает RBAC, режим наблюдения `observe`, human-in-the-loop (`approve`), аудит в SQLite и полигон Red Team.

## Быстрый старт (новый коллаборатор / Claude Code)

```bash
git checkout feat/demo-day-and-v02
python -m venv .venv                       # или: uv venv .venv
# Windows: .venv\Scripts\activate  |  Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
pip install python-docx python-pptx pillow lxml   # только если пересобирать презентации/паспорт
cp .env.example .env                       # при необходимости; .env в .gitignore
```

## Команды запуска и проверки

```bash
pytest -q                                  # все автотесты (работает напрямую благодаря pyproject.toml)
python -m axisec                           # http://127.0.0.1:8080 (--mode observe --workers 4 --policy ...)
python bench/latency.py                    # замеры задержки движка и HTTP -> bench/results.json
python bench/load.py                       # нагрузочный тест 50-200 клиентов -> bench/load_results.json
python -m axisec.redteam.live_eval --help  # прогон 14 атак + 8 задач на реальных LLM
python deck/build_decks.py                 # пересборка презентаций -> deliverables/*.pptx
python deck/build_passport.py              # пересборка паспорта -> deliverables/Axisec_passport.docx
```

Docker-сборка (учёт лимита 429 Docker Hub):
```bash
docker build --build-arg PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim -t axisec .
```

## Состав кода

- `axisec/policy.py`, `axisec/engine.py` — модель YAML-политики (`SqlRules`, `ShellRules`, `PathRules`, `RolePolicy`) и движок решений (RBAC, `allow`/`modify`/`approve`/`block`, теги OWASP).
- `axisec/guards/` — `sql.py` (SQLite/PostgreSQL/MySQL, блок `/*!...*/`), `shell.py` (`shlex`), `path.py`, `args.py`, `dlp.py` (+ `StreamMasker`).
- `axisec/gateway/` — `app.py` (FastAPI + REST/SSE/SIEM/Prometheus), `proxy.py` (LLM+MCP прокси и SSE-стриминг), `providers.py` (OpenAI, GigaChat OAuth2+`functions`, Yandex AI Studio), `auth.py` (admin/gateway токены + привязка ролей).
- `axisec/approvals.py`, `axisec/policy_draft.py`, `axisec/audit.py` — очередь подтверждений человеком, автогенератор черновика YAML из `tools/list`, персистентный SQLite-аудит, экспорт JSONL/CEF и `/metrics`.
- `axisec/redteam/` — `scenarios.yaml` (14 атак + 8 задач), `corpus.yaml` (CRM SQLite), `corpora/` (`postgres.yaml`, `mysql.yaml`, `shell.yaml`, `path.yaml`), `runner.py`, `live_eval.py`.
- `axisec/demo/` и `axisec/dashboard/index.html` — стенд «Ромашка», имитатор `mock_llm.py`, MCP-сервер и веб-интерфейс.

## Обязательные правила проекта

- **Ветвление и Vercel:** основная ветка `ccr-bca1b7b0-rcgzee` — она же production для Vercel (пуш в неё запускает деплой). Новая разработка идёт в отдельной ветке (`feat/demo-day-and-v02`) до утверждения пользователем. В деплой идут только код и политики (`.vercelignore` и `vercel.json` исключают `source/`, `deliverables/`, `deck/`, `docs/`, `tests/`, `bench/`, `.env*`).
- **`source/` — оригиналы команды, только чтение.**
- **Цифра на слайде имеет происхождение:** измеренная сначала попадает в `docs/02_mvp_results.md`, взятая из источника — в `docs/01_research_factcheck.md`, и только потом на слайд.
- **Презентации и паспорт собираются скриптами:** правка идёт в `deck/build_decks.py` и `deck/build_passport.py`, текст выступления — в `deliverables/speech_5min.md` между метками `<!-- slide: -->` (попадает в заметки слайдов). После пересборки обязательно экспортируй/отрендери изменённые слайды в картинки и проверь визуально: в шаблоне шрифт `Helvetica Neue`, здесь он подменяется, нужен запас по ширине и контроль переполнения.
- **Канонические роли команды** (по `source/passport_original.docx`): Андросик Стефан Витальевич (Team Lead / Архитектор ИБ), Малюгин Егор Андреевич (ядро шлюза / Backend), Мотов Александр Олегович (Red Team / Frontend).
- **Ущерб и корпуса:** ущерб считается по состоянию демо-мира (`World.harms`), а не по логам шлюза. Новая атака в `scenarios.yaml` обязана наносить ущерб без шлюза (`test_red_team_suite`). Новое правило движка получает и блокируемые, и легитимные примеры в `corpus.yaml` или `corpora/*.yaml`.
- **Имитатор модели** (`axisec/demo/mock_llm.py`) намеренно послушный: выполняет любую найденную инструкцию.
- **Секреты:** никогда не коммить `.env`, ключи API и личные токены.
