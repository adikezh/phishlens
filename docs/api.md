# API

Спецификация: [api/openapi.yaml](../api/openapi.yaml). Быстрые примеры:

```bash
# текст
curl -s localhost:8082/v1/analyze -H 'Content-Type: application/json' \
  -d '{"text":"From: Kaspi <x@kaspi-login.top>\nSubject: Срочно\n\nВведите код из SMS: http://kaspi-login.top/v","lang":"ru"}' | jq .result.verdict

# .eml файл
curl -s localhost:8082/v1/analyze -F file=@testdata/eml/phish_kaspi_01.eml | jq '.result | {score, verdict, attack_type}'

# демо-пример
curl -s localhost:8082/v1/analyze -F demo=bec_ceo_01 | jq .result.score

# с ключом (phishlens apikey create --role analyst)
curl -s "localhost:8082/v1/submissions?since=7d" -H "X-API-Key: pl_..."
```

Коды ошибок: `400 bad_request`, `401 unauthorized`, `403 forbidden`, `404 not_found`, `413 too_large`,
`415 unsupported`, `422 parse_error`, `429 rate_limited`, `501 not_implemented`.
