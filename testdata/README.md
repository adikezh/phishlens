# Корпус (ТЗ §10)

- `eml/` — размеченные письма: 3 демонстрационных и 200 воспроизводимых синтетических вариантов (100 phishing, 100 clean). Публичные датасеты пока не включены: см. [границу provenance](../docs/corpus-provenance.md).
- `expected/<name>.json` — золотой вердикт: `verdict`, опц. `attack_type`, `min_score`/`max_score`, `signals` (обязаны присутствовать).
- `msg/`, `images/`, `attachments/` — входы для MSG, OCR и анализа вложений.

Прогон: `phishlens eval --dir testdata/eml --expected testdata/expected` (офлайн по умолчанию; `--online` включает DNSBL/TI).
CI ломает сборку при macro-F1 < 0.9 (`--min-f1 0.9`).
