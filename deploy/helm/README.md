# PhishLens Helm chart

This chart deploys the Community service with a SQLite PVC by default. The
container runs as UID/GID 65532 with a read-only root filesystem, dropped Linux
capabilities, a memory-backed `/tmp`, and no service-account token mount.

```bash
helm install phishlens ./deploy/helm \
  --set image.tag=v0.2.4 \
  --set existingSecret=phishlens-secrets
```

`existingSecret` is optional for demo mode and should contain `PL_ENC_KEY`,
`URLHAUS_AUTH_KEY`, and any configured LLM/provider credentials. Enable the
Ingress only with an ingress controller and TLS policy appropriate for the
cluster. PostgreSQL is not silently enabled by this chart; the current verified
storage backend is SQLite.
