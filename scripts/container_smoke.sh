#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE="${1:-phishlens:ci}"
NAME="phishlens-smoke-${RANDOM}-${RANDOM}"
VOLUME="phishlens-smoke-${RANDOM}-${RANDOM}"
PORT="${PHISHLENS_SMOKE_PORT:-18082}"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$VOLUME" >/dev/null
docker run --rm --user 0:0 -v "$VOLUME:/app/var" alpine:3.22 \
  sh -ec 'mkdir -p /app/var; chown -R 65532:65532 /app/var; stat -c "%u:%g" /app/var'

docker run -d --name "$NAME" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  -p "${PORT}:8082" \
  -e 'PL_STORAGE_DSN=file:/app/var/phishlens.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)' \
  -v "$VOLUME:/app/var" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${PORT}/health" > /tmp/phishlens-health.json; then
    break
  fi
  sleep 1
done

test -s /tmp/phishlens-health.json
grep -q '"status":"ok"' /tmp/phishlens-health.json
curl --fail --silent "http://127.0.0.1:${PORT}/addins/outlook/manifest.xml" >/dev/null
curl --fail --silent "http://127.0.0.1:${PORT}/addins/outlook/icon-128.png" >/dev/null
python scripts/demo_smoke.py "http://127.0.0.1:${PORT}"

test "$(docker inspect -f '{{.Config.User}}' "$NAME")" = "nonroot:nonroot"
cat /tmp/phishlens-health.json
echo "container smoke passed: ${IMAGE}"
