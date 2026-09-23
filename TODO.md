# PhishLens — evidence-backed delivery status

This file separates the runnable Community release from Business integrations
that require external accounts, providers, or deployment-specific decisions.

## Confirmed in this checkout

- Go build succeeds with Go 1.26.7 on Windows amd64.
- `go test ./...` passes.
- The deterministic demo corpus contains three EML messages and passes
  `phishlens eval` with macro-F1 1.00.
- CLI text/EML analysis works without an LLM and keeps reputation failures as
  explicit degradation warnings.
- The HTTP service exposes `/health`, `/metrics`, `/v1/analyze`, analysis
  retrieval, API-key authentication, SQLite persistence, allow/block lists,
  brands, statistics, and analyst review status.
- Confirmed phishing IOCs are retained without message bodies and export as
  STIX 2.1 or MISP JSON through `phishlens ioc export`.
- Configured Wazuh HTTP delivery sends thresholded, privacy-safe verdict events
  with Basic Auth; unavailable Wazuh is reported as a degraded notification.
- Admin API manages org-scoped HMAC webhook subscriptions; secrets are
  encrypted at rest and managed subscriptions are delivered on verdicts.
- `phishlens report` now emits Markdown, minimal valid DOCX, and PDF formats
  from privacy-safe aggregate statistics.
- Helm chart renders and lints with PVC-backed SQLite, probes, resource limits,
  non-root/read-only security controls, and optional existingSecret/Ingress.
- Analyst API actions now support campaign grouping, blocklisting a domain from
  a submission, and local incident escalation with audit records.
- Community storage defaults to metadata/signals only; message bodies require
  explicit `storage.store_bodies=true` and an encryption key for encrypted
  storage.
- PostgreSQL storage is implemented through pgx with the same Store contract;
  hosted CI runs migrations and CRUD/statistics integration tests against a
  disposable PostgreSQL service.
- Local `govulncheck ./...` reports no vulnerabilities in reachable code paths;
  one unrelated vulnerability remains in a required-but-unreachable module.

## Community v1 gates still to close

- [ ] Add a larger, licensed/synthetic regression corpus before making any
  accuracy claim beyond the three demo messages.
- [ ] Add API/UI end-to-end tests against a started server, including upload
  limits, API-key roles, persistence, and deletion.
- [x] Add fuzz tests for text/EML dispatch, HTML/URL extraction, and attachment listing paths.
- [x] Docker Compose runtime smoke: init volume ownership, non-root image,
  read-only rootfs, no-new-privileges, and `/health` verified locally.
- [x] Community PDF static analysis: bounded URL/text extraction and active
  feature detection without rendering or executing PDF actions. PDF OCR remains
  an optional OCR/Business extension.

## Business / external gates (not locally provable)

- IMAP, Microsoft Graph, Telegram, Outlook/Gmail add-in host validation.
- Configure and verify a real URLhaus Auth-Key; without it the provider is explicitly degraded to unknown.
- Live Safe Browsing/AbuseIPDB/VirusTotal accounts and rate limits.
- OIDC, multi-tenant production isolation, live TheHive/IRIS/Jira account integration.
- Sandbox isolation and browser detonation evidence.
- Pilot evidence: one organization, two weeks, at least 20 real submissions,
  measured false positives/negatives, and owner-approved weight changes.
- Public demo, registry publication, and operational backup/restore.

## Required release evidence

Every release must record the exact commit, Go version, test commands and
results, dependency/security scan output, container digest, configuration
defaults, and the external gates that remain unverified. A green local test is
not evidence for hosted-provider behavior or production readiness.
