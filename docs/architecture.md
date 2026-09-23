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
└────────────┘             └───────────────────────────────────────────┘          * = заглушка
```

## Принципы (ТЗ §2)

- **Сигнал — единица доказательства.** Каждая эвристика возвращает `domain.Signal{ID, Category, Weight, Confidence, Evidence, Explanation, Source}`. Вердикт = `clamp(Σ weight×confidence)` + жёсткие правила (`internal/score`). LLM — только категория `semantic` (±25) и объяснение; он не может поставить `clean` при сильном техническом сигнале (→ `needs_review`).
- **Деградация вместо падения.** Ошибка любой сетевой стадии (DNSBL, TI, LLM) даёт `Analysis.Warnings[]`, а не ошибку запроса. `app.Options.Offline` полностью отключает сеть (batch/eval/тесты).
- **PII не покидает процесс.** `llm.Redactor` заменяет email/телефон/ИИН/карту/IBAN плейсхолдерами до любого внешнего вызова; словарь замен не сохраняется.
- **Приватность по умолчанию.** `storage.store_bodies=false` → в БД только метаданные, скор и сигналы без evidence.

## Контракты между слоями

| Интерфейс | Где | Реализации |
|---|---|---|
| `signals.Check` | `internal/signals` | ~40 функций в `signals/<category>/` |
| `signals.BrandLookup` | `internal/signals` | `brands.Matcher` |
| `signals.ListLookup` | `internal/signals` | `app.storeLists` (allow/block из БД) |
| `signals.ReputationLookup` | `internal/signals` | `reputation.Client` (DNSBL, OpenPhish, RDAP; URLhaus with Auth-Key) |
| `llm.Provider` | `internal/llm` | `OpenAICompatible`, `Anthropic` (official SDK), `Ollama` |
| `parse.OCR` | `internal/parse` | `TesseractOCR` (HTTP к контейнеру), vision-LLM — TODO |
| `store.Store` | `internal/store` | `SQLite` (modernc) and PostgreSQL (pgx), shared contract/migrations |
| `notify.Notifier` | `internal/notify` | HMAC webhook and privacy-safe Wazuh HTTP delivery; TheHive remains a Business TODO |
| `ingest.Runner` | `internal/ingest` | imap / graph / telegram — TODO |

## Добавление сигнала

1. Файл `internal/signals/<category>/<hxx>_<name>.go` с функцией `func(ctx, *signals.Input) ([]domain.Signal, error)`.
2. Константа ID `"<category>.<name>"`, регистрация в `register.go` категории.
3. Ключ объяснения в `internal/i18n/locales/{ru,en,kz}.yaml` (тест `TestCatalogParity` проверит паритет).
4. Вес в `data/weights.yaml` (иначе останется дефолт из кода).
5. Тест: ≥3 позитивных и ≥3 негативных кейса. Страница `docs/signals/<id>.md`.

## Данные и встраивание

`data/`, `prompts/`, `migrations/`, `addins/` встроены через `embed.FS`; файлы на диске (`analysis.data_dir`, `weights_file`, `brands_file`, `prompts_dir`) имеют приоритет. Бинарь работает без внешних файлов.

## Что заглушено

См. `grep -rn "TODO(" internal/` — каждая заглушка ссылается на пункт ТЗ.
