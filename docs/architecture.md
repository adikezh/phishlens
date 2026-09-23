# Архитектура PhishLens (каркас)

```
 Входы                       Ядро анализа (internal/app.Analyzer)                 Выходы
┌────────────┐   Request   ┌───────────────────────────────────────────┐        ┌──────────────┐
│ Web UI     │────────────▶│ 1. parse      internal/parse   eml/text/… │        │ JSON / UI    │
│ REST API   │             │ 2. brand      internal/brands              │──────▶ │ store (SQLite│
│ CLI        │             │ 3. heuristics internal/signals/{header,…}  │        │ notify:      │
│ Outlook*   │             │ 4. reputation internal/reputation (+cache) │        │  webhook HMAC│
│ Gmail*     │             │ 5. llm        internal/llm  (redact → JSON)│        │  wazuh*      │
│ IMAP/Graph*│             │ 6. semantic   internal/signals/semantic    │        │  thehive*    │
│ Telegram*  │             │ 7. score      internal/score               │        └──────────────┘
└────────────┘             └───────────────────────────────────────────┘          * = внешняя среда
```

## Принципы (ТЗ §2)

- **Сигнал — единица доказательства.** Каждая эвристика возвращает `domain.Signal{ID, Category, Weight, Confidence, Evidence, Explanation, Source}`. Вердикт = `clamp(Σ weight×confidence)` + жёсткие правила (`internal/score`). LLM — только категория `semantic` (±25) и объяснение; он не может поставить `clean` при сильном техническом сигнале (→ `needs_review`).
- **Деградация вместо падения.** Ошибка любой сетевой стадии (DNSBL, TI, LLM) даёт `Analysis.Warnings[]`, а не ошибку запроса. `app.Options.Offline` полностью отключает сеть (batch/eval/тесты).
- **PII не покидает процесс.** `llm.Redactor` заменяет email/телефон/ИИН/карту/IBAN плейсхолдерами до любого внешнего вызова; словарь замен не сохраняется.
- **Приватность по умолчанию.** `storage.store_bodies=false` → в БД только метаданные, скор и сигналы без evidence.

## Контракты между слоями

| Интерфейс | Где | Реализации |
|---|---|---|
| `signals.Check` | `internal/signals` | 60 зарегистрированных проверок в `signals/<category>/` |
| `signals.BrandLookup` | `internal/signals` | `brands.Matcher` |
| `signals.ListLookup` | `internal/signals` | `app.storeLists` (allow/block из БД) |
| `signals.ReputationLookup` | `internal/signals` | `reputation.Client` (DNSBL, OpenPhish, RDAP; URLhaus with Auth-Key) |
| `llm.Provider` | `internal/llm` | `OpenAICompatible`, `Anthropic` (official SDK), `Ollama` |
| `parse.OCR` | `internal/parse` | `TesseractOCR` or vision-LLM through Ollama/OpenAI-compatible provider |
| `store.Store` | `internal/store` | `SQLite` (modernc) and PostgreSQL (pgx), shared contract/migrations |
| `notify.Notifier` | `internal/notify` | HMAC webhook (static and encrypted org subscriptions), privacy-safe Wazuh, TheHive 5, DFIR-IRIS v2, and Jira REST delivery |
| `ingest.Runner` | `internal/ingest` | IMAPS, Microsoft Graph delta, and Telegram Bot API implemented |

Browser OIDC login is implemented in `internal/httpapi/oidc.go`: discovery,
authorization state, nonce and audience verification, signed HttpOnly sessions,
and default-deny group-to-role mapping. A live identity provider and
deployment-specific claim mapping remain external evidence gates.

The Telegram receiver uses `getUpdates`, `getFile`, and `sendMessage` with
bounded HTTP calls; `/start <org-code>` creates an in-memory organization
binding and message/photo content is passed to `app.Analyzer`.

When `ocr.mode=vision_llm`, `parse.VisionOCR` calls the configured
vision-capable LLM provider for transcription only; URLs and verdict signals
are still produced by the deterministic parser/scoring pipeline.

Long-running REST analyses reserve their submission ID first; the handler waits
up to ten seconds, then returns `202` with a polling `Location` while the
analyzer updates that same stored resource.

## Добавление сигнала

1. Файл `internal/signals/<category>/<hxx>_<name>.go` с функцией `func(ctx, *signals.Input) ([]domain.Signal, error)`.
2. Константа ID `"<category>.<name>"`, регистрация в `register.go` категории.
3. Ключ объяснения в `internal/i18n/locales/{ru,en,kz}.yaml` (тест `TestCatalogParity` проверит паритет).
4. Вес в `data/weights.yaml` (иначе останется дефолт из кода).
5. Тест: ≥3 позитивных и ≥3 негативных кейса. Страница `docs/signals/<id>.md`.

## Данные и встраивание

`data/`, `prompts/`, `migrations/`, `addins/` встроены через `embed.FS`; файлы на диске (`analysis.data_dir`, `weights_file`, `brands_file`, `prompts_dir`) имеют приоритет. Бинарь работает без внешних файлов.

`phishlens report --format awareness` строит обезличенные HTML-карточки из
подтверждённых кейсов: в экспорт не попадают тема, адреса, тело или ID
обращения; остаются только вердикт, score, бренд, ограниченный список сигналов
и общие уроки для сотрудника.

## Граница проверки

Реализованные адаптеры внешних систем всё равно требуют отдельной live-проверки
с реальным аккаунтом и сетевой политикой. Матрица требований, команд проверки и
остаточных внешних гейтов находится в [tz-audit.md](tz-audit.md).
