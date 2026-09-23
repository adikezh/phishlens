# Корпус (ТЗ §10)

- `eml/` — размеченные письма. Цель ≥ 200: свои синтетические + публичные (Nazario, SpamAssassin, APWG-подобные). Сейчас — 3 демо-примера.
- `expected/<name>.json` — золотой вердикт: `verdict`, опц. `attack_type`, `min_score`/`max_score`, `signals` (обязаны присутствовать).
- `msg/`, `images/`, `attachments/` — входы для .msg-парсера, OCR и анализа вложений (TODO).

Прогон: `phishlens eval --dir testdata/eml --expected testdata/expected` (офлайн по умолчанию; `--online` включает DNSBL/TI).
CI ломает сборку при macro-F1 < 0.9 (`--min-f1 0.9`).
