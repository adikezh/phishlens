# Развёртывание

## Бинарь
```bash
go build -o phishlens ./cmd/phishlens
cp configs/config.example.yaml configs/config.yaml   # правьте под себя
./phishlens migrate up
./phishlens apikey create --name outlook-addin --role user
./phishlens serve
```

## Docker
```bash
docker compose -f deploy/docker-compose.yml up --build
```
Образ — distroless, non-root, read-only FS; данные в volume /app/var.

## systemd
deploy/systemd/phishlens.service; секреты — в /etc/phishlens/env (OPENROUTER_KEY=…, PL_ENC_KEY=…).

## Переменные окружения
Любой ключ конфига: `PL_<SECTION>_<KEY>` (PL_SERVER_LISTEN, PL_LLM_ENABLED, PL_STORAGE_DSN).
Ключи API/провайдеров — по именам из `*_env` полей конфига.

## Helm / Kubernetes
Для прямого HTTPS задайте `server.tls.cert` и `server.tls.key` одновременно;
сервер запустит `ListenAndServeTLS`. Если поля пусты, используется HTTP — это
подходит для локальной разработки или TLS-терминации на ingress. Helm-пример и
секреты сертификата описаны в `deploy/helm/README.md`.
