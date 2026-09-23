# Audit of TZ_05_phishlens

This is the delivery audit for the original specification. It deliberately
separates implementation from evidence: a mock, a local unit test, or a green
CI job does not prove behavior of a real M365 tenant, reputation provider, or
customer pilot.

## Requirement matrix

| TZ area | Current implementation | Evidence in this checkout | Status |
|---|---|---|---|
| Web/API/text/EML/MSG/image/PDF/Telegram inputs | Shared parser and analyzer paths; bounded uploads; Telegram polling | `go test ./...`, `scripts/ui_smoke.py`, parser tests | Implemented locally |
| 60+ deterministic signals | 60 registered checks, localized explanations, weights, docs parity | `internal/signals/all`, `docs/signals`, CI tests | Implemented and CI-checked |
| 100+ brands, domain/keyword/logo/color matching | 100+ YAML brands; pHash and palette matching; custom brands | `internal/brands`, `internal/store/brands_test.go`, migration 0005 | Implemented locally; visual data quality remains a data gate |
| LLM explanation and vision OCR | OpenAI-compatible, Anthropic, Ollama adapters; redaction, schema validation, cache; vision is advisory | LLM unit tests and offline path | Implemented; live provider/model remains external |
| Score and hard rules | Weighted signals, thresholds, allow/block lists, technical rules cannot be overridden by LLM clean | score and analyzer tests | Implemented locally |
| Queue, campaigns, review actions, reports, IOC/STIX/MISP, awareness | API/UI/store/report/notification paths are present | HTTP/API, report, review, and integration tests | Implemented locally |
| IMAP, Graph, Outlook/Gmail add-ins | Bounded receivers and static add-in bundles | package tests and static inspection | Code implemented; live host validation remains external |
| Wazuh/webhook/TheHive/IRIS/Jira | Privacy-safe outbound adapters with bounded requests | notifier tests | Code implemented; real account/permission tests remain external |
| OCR container | Tesseract HTTP adapter with ru/en/kz data, limits, timeout and isolation | local Docker build/health smoke and hosted OCR build | Implemented and build-verified |
| Sandbox | Remote Chrome client with SSRF checks and isolated image | sandbox unit tests and Dockerfile | Code implemented; egress proxy and browser smoke remain external |
| Performance and reliability | Offline p95 gate for 50 concurrent analyses; timeouts/circuit breakers/degraded warnings | `docs/performance.md`, local test, hosted race/build | Partially verified; full-provider p95 is deployment-specific |
| Privacy/security | no-body Community default, AES-GCM option, PII redaction, deletion, TLS, rate limiting, non-executing parsers | privacy/threat-model docs, tests, CI security jobs | Implemented locally; deployment controls need operator evidence |

## Release gates still requiring external state

- a licensed/public real-world corpus and a representative multilingual OCR
  corpus; the current F1 gate uses 200 reproducible synthetic messages;
- a public HTTPS demo and registry publication;
- live M365/Gmail/IMAP/Telegram, OIDC, Wazuh/SOAR and reputation-provider
  credentials, permissions, rate limits, and provider responses;
- an isolated sandbox deployment with an approved egress proxy/network policy;
- a two-week pilot in one organization with at least 20 real submissions,
  measured false positives/negatives, and approved weight changes.

These are not silently marked complete by local tests. The authoritative running
status is maintained in [TODO.md](../TODO.md), and each release should record
the commit, toolchain, commands, CI run, image digest, and remaining gates.
