# phishlens-ocr: Tesseract с ru/en/kaz traineddata за минимальным HTTP API.
FROM golang:1.26.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY deploy/ocr ./deploy/ocr
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/phishlens-ocr ./deploy/ocr

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng tesseract-ocr-kaz ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/phishlens-ocr /usr/local/bin/phishlens-ocr
RUN useradd --system --uid 65532 --no-create-home phishlens
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/phishlens-ocr"]
CMD ["--listen", ":8090"]
