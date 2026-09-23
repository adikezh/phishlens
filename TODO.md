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
- Community storage defaults to metadata/signals only; message bodies require
  explicit `storage.store_bodies=true` and an encryption key for encrypted
  storage.
- Local `govulncheck ./...` reports no vulnerabilities in reachable code paths;
  one unrelated vulnerability remains in a required-but-unreachable module.

## Community v1 gates still to close

- [ ] Add a larger, licensed/synthetic regression corpus before making any
  accuracy claim beyond the three demo messages.
- [ ] Add API/UI end-to-end tests against a started server, including upload
  limits, API-key roles, persistence, and deletion.
- [ ] Add fuzz tests for EML, HTML, URL, and attachment listing paths.
- [ ] Add a production deployment smoke test for Docker Compose and verify the
  image is non-root and read-only at runtime.
- [ ] Decide whether PDF OCR belongs in Community or is a licensed Business
  component; do not silently treat unsupported formats as analysed.

## Business / external gates (not locally provable)

- IMAP, Microsoft Graph, Telegram, Outlook/Gmail add-in host validation.
- Live TI/RDAP/Safe Browsing/AbuseIPDB/VirusTotal accounts and rate limits.
- OIDC, multi-tenant production isolation, SIEM/SOAR account integration.
- Sandbox isolation and browser detonation evidence.
- Pilot evidence: one organization, two weeks, at least 20 real submissions,
  measured false positives/negatives, and owner-approved weight changes.
- Public demo, hosted CI, registry publication, and operational backup/restore.

## Required release evidence

Every release must record the exact commit, Go version, test commands and
results, dependency/security scan output, container digest, configuration
defaults, and the external gates that remain unverified. A green local test is
not evidence for hosted-provider behavior or production readiness.
