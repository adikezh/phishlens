# Public HTTPS demo deployment

The GitHub Pages site is a public static landing. A live API demo must run on
an operator-controlled HTTPS host; this guide deploys the Community image with
the repository's Helm chart. It does not create credentials or expose a
cluster automatically.

## Prerequisites

- Kubernetes cluster with a default StorageClass and an Ingress controller;
- a DNS record pointing `phishlens.example.com` to the Ingress address;
- cert-manager (or an existing TLS secret) and an approved egress policy;
- Helm 3 and access to the public GHCR image.

Create only the secrets required by the enabled integrations. The Community
default stores metadata only and keeps LLM, OCR, sandbox, and provider-backed
features disabled.

```bash
kubectl create namespace phishlens
kubectl -n phishlens create secret generic phishlens-secrets \
  --from-literal=PL_ENC_KEY="$(openssl rand -base64 32)"
```

Install the pinned release and enable the Ingress. Replace the host and TLS
issuer with values approved for the target cluster:

```bash
helm upgrade --install phishlens ./deploy/helm \
  --namespace phishlens \
  --set image.repository=ghcr.io/adikezh/phishlens \
  --set image.tag=v0.2.5 \
  --set existingSecret=phishlens-secrets \
  --set config.server.base_url=https://phishlens.example.com \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.hosts[0].host=phishlens.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix \
  --set ingress.tls[0].hosts[0]=phishlens.example.com \
  --set ingress.tls[0].secretName=phishlens-tls
```

Verify from outside the cluster before calling it a public demo:

```bash
curl --fail https://phishlens.example.com/health
curl --fail https://phishlens.example.com/v1/demos
python scripts/demo_smoke.py https://phishlens.example.com
```

The final command is the acceptance check for the three examples and the
five-second response requirement. Record the cluster, image digest, TLS
configuration, provider settings, and command output in the release evidence.
Until those checks run against a real host, the public-demo gate remains open.
