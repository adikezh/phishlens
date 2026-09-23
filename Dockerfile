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
USER nonroot:nonroot
EXPOSE 8082
VOLUME ["/app/var"]
ENTRYPOINT ["/app/phishlens"]
CMD ["serve", "--config", "/app/configs/config.yaml"]
