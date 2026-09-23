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
- Direct HTTPS is supported by `server.tls.cert` + `server.tls.key`, with
  configuration validation preventing one-sided TLS settings.
- Business licensing now requires an Ed25519 signature, configured public key,
  valid edition/org claims, and an optional non-expired `expires_at` claim.
- Analyst API actions now support campaign grouping, blocklisting a domain from
  a submission, and local incident escalation with audit records.
- `phishlens weights tune` now calibrates bounded signal weights from analyst
  JSONL labels and writes a reproducible YAML override file.
- L-07 tracking pixels and missing unsubscribe instructions are detected from
  inline-image metadata/HTML and marketing-language context.
- L-08 QR codes in image submissions are decoded locally; only HTTP(S) QR
  payloads are added to the normal link-analysis path.
- L-03 known shorteners are expanded with bounded HEAD redirects and private/
  local-address rejection; expansion is disabled in offline mode.
- H-05 Received IPs can be checked through the existing TI reputation contract;
  H-07 detects known bulk-mailer headers on single-recipient messages.
- C-06 recognizes valid 12-digit Kazakhstan IIN/BIN checksums as additional
  finance-request evidence.
- A-02 lists ZIP, RAR4, and 7z entries without extracting files; encrypted
  archives remain explicit signals and archive executable names are inspected.
  RAR5 is intentionally opaque because safe metadata-only parsing is not yet
  implemented.
- A-03 detects VBA directory markers in legacy OLE Office attachments without
  opening or executing macro streams.
- C-04 compares detected message language with the configured brand locale;
  unknown language and machine-translation claims remain out of scope.
- TheHive 5 notifier posts privacy-safe alerts with domains and attachment
  hashes, bearer authentication, organisation routing, verdict thresholding,
  bounded timeouts, and non-secret error handling. A live TheHive account is
  still required for external verification.
- OIDC login/callback/logout now verify provider discovery, authorization state,
  ID-token audience and nonce, and issue signed HttpOnly sessions with default-
  deny role mapping. A live IdP, group/tenant claim mapping, rotation and
  multi-instance session test remain deployment gates.
- REST analysis now reserves an ID, returns the completed result within the
  10-second synchronous budget, or returns `202 Accepted` with `Location` and
  `Retry-After` while the same persisted resource is processed.
- Telegram receiver now implements bounded Bot API long polling, `/start
  <org-code>` binding, text/photo intake, a 10 MiB photo limit, and verdict
  replies through the shared analyzer. A live bot token and organization
  binding procedure remain external verification gates.
- Outlook add-in now reads Office MIME slices correctly, supports SSO cookie or
  operator-entered API key without shipping a credential, polls `202` results,
  and declares a VersionOverrides ribbon command. Sideloading in a real M365
  tenant and HTTPS/manifest validation remain external gates.
- IMAP receiver now polls IMAPS for unseen messages with a 25 MiB bound, sends
  `.eml` through the shared analyzer, marks only successful messages as seen,
  optionally moves them to `processed_folder`, and supports an explicit
  privacy-safe SMTP verdict reply.
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
- [x] Black-box API/UI E2E script against a started server covers persistence,
  retrieval, user-vs-admin queue RBAC, deletion, and browser-visible admin key
  loading. Verified locally on 2026-09-23 with `python scripts/ui_smoke.py
  http://127.0.0.1:18083 --admin-key <admin> --user-key <user>` against a
  real `phishlens serve` process. With `--max-upload-mb 1`, the same script
  also verifies an oversized multipart request returns HTTP 413.
- [x] Add deterministic local weight tuning from analyst labels; pilot owners
  still must review and approve any tuned weights before deployment.
- [x] Add fuzz tests for text/EML dispatch, HTML/URL extraction, and attachment listing paths.
- [x] Docker Compose runtime smoke: init volume ownership, non-root image,
  read-only rootfs, no-new-privileges, and `/health` verified locally.
- [x] Community PDF static analysis: bounded URL/text extraction and active
  feature detection without rendering or executing PDF actions. PDF OCR remains
  an optional OCR/Business extension.

## Business / external gates (not locally provable)

- Microsoft Graph, Gmail add-in host validation, and live IMAP/Outlook/M365
  provider/host validation, plus Telegram bot/token verification.
- Configure and verify a real URLhaus Auth-Key; without it the provider is explicitly degraded to unknown.
- Live Safe Browsing/AbuseIPDB/VirusTotal accounts and rate limits.
- Live OIDC IdP/group/tenant verification, multi-tenant production isolation,
  live TheHive account verification,
  and IRIS/Jira account integration.
- Sandbox isolation and browser detonation evidence.
- Pilot evidence: one organization, two weeks, at least 20 real submissions,
  measured false positives/negatives, and owner-approved weight changes.
- Public demo, registry publication, and operational backup/restore.

## Required release evidence

Every release must record the exact commit, Go version, test commands and
results, dependency/security scan output, container digest, configuration
defaults, and the external gates that remain unverified. A green local test is
not evidence for hosted-provider behavior or production readiness.
