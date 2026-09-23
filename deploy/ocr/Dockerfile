# phishlens-ocr: tesseract с ru/en/kaz traineddata за минимальным HTTP API (F-4.1.9).
# POST /ocr  (body = image bytes, Content-Type image/*) → {"text": "...", "urls": [...]}
# TODO: реализовать сервер (Go + otiai10/gosseract, cgo) — этот Dockerfile только описывает контракт.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng tesseract-ocr-kaz ca-certificates \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 8090
# COPY phishlens-ocr /usr/local/bin/phishlens-ocr
# ENTRYPOINT ["phishlens-ocr", "--listen", ":8090"]
CMD ["tesseract", "--version"]
