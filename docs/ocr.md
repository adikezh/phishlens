# Local OCR container

`deploy/ocr` is a real Tesseract HTTP adapter, not a placeholder image. It
supports Russian, English, and Kazakh trained data and exposes:

- `GET /health` — readiness response;
- `POST /ocr` with `Content-Type: image/*` — `{text, urls}`.

The adapter bounds the image body to 25 MiB, runs Tesseract with a timeout,
writes the input to a mode-0600 temporary file, removes it after the command,
and never executes or extracts an attachment. The main service treats OCR
failures as an explicit degraded warning.

Run it with Compose:

```powershell
$env:PL_OCR_MODE = "tesseract"
$env:PL_OCR_TESSERACT_URL = "http://ocr:8090"
docker compose -f deploy/docker-compose.yml --profile ocr up --build
```

The service is isolated with a read-only root filesystem, a `noexec` `/tmp`,
dropped capabilities, and `no-new-privileges`. The image build and HTTP smoke
are part of the local acceptance evidence; OCR language quality still needs a
representative multilingual image corpus.
