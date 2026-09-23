# Sandbox detonation

Business mode uses `internal/sandbox` to drive a separate Chrome DevTools
endpoint. The PhishLens process does not launch Chrome itself. Before a page is
navigated, its hostname is resolved and loopback, RFC1918, link-local, ULA,
multicast, unspecified, and cloud metadata addresses are rejected. The runner
uses a fresh target, clears browser cookies, applies a fixed User-Agent, and
enforces a 15-second default deadline.

The result contains the final URL, whether an `input[type=password]` was
rendered, the page title, and an optional PNG screenshot. L-05 emits a signal
only when the login form is not on the matched brand's official domain.

The browser must be deployed with a separate network policy and an explicit
egress proxy/allow-list. `network_mode: none` without a proxy intentionally
does not provide a usable detonation path; enable the runner only after that
deployment boundary is configured and smoke-tested.
