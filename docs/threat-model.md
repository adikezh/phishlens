# PhishLens security boundary and release assumptions

## Assets

- Submitted email text, headers, URLs, attachments, screenshots, and OCR text.
- API keys, organization membership, allow/block lists, analyst decisions, and
  audit records.
- External-provider prompts and responses, including the redacted data sent to
  LLM/TI services.

## Trust boundaries

1. Browser, add-in, bot, or API client to the HTTP service: all fields and the
   claimed organization are untrusted.
2. Uploaded MIME/HTML/archive/image data to parsers: data is adversarial and
   must remain bounded, non-executable, and in memory/tmpfs where possible.
3. PhishLens to DNS/TI/LLM/webhook providers: external calls can fail, lie,
   time out, or return prompt-injection content.
4. Analyst actions to storage and outbound integrations: authorization and
   audit logging are required.

## Enforced Community controls

- Upload size and image-pixel limits.
- No execution of attachments; static listing only.
- URL checks must reject private/link-local/metadata destinations before any
  network fetch.
- API-key hashes are stored instead of plaintext keys; role checks are server
  side.
- LLM is optional, receives redacted content, and cannot override hard
  technical rules.
- Community defaults to not storing message bodies.
- Security response headers, rate limiting, and structured audit records exist
  on the API path.

## Residual risks / owner decisions

- A deployed instance still needs TLS termination, secret rotation, backups,
  tenant-specific authorization policy, and a real provider configuration.
- External reputation results are advisory and may be unavailable or stale.
- The demo corpus is not a representative detection benchmark.
- `.msg`, PDF OCR, sandboxing, and provider integrations must not be enabled in
  production until their isolation and failure behavior are tested directly.
