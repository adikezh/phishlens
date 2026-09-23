# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/phishlens/phishlens/internal/buildinfo.Version=${VERSION}" \
    -o /out/phishlens ./cmd/phishlens

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/phishlens /app/phishlens
COPY configs/config.example.yaml /app/configs/config.yaml
COPY data /app/data
COPY prompts /app/prompts
USER nonroot:nonroot
EXPOSE 8082
VOLUME ["/app/var"]
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 CMD ["/app/phishlens", "healthcheck", "--url", "http://127.0.0.1:8082/health"]
ENTRYPOINT ["/app/phishlens"]
CMD ["serve", "--config", "/app/configs/config.yaml"]
