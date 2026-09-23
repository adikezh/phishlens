"""Black-box smoke test for the three built-in API demonstrations."""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEMOS = {"bec_ceo_01", "clean_bank_01", "phish_kaspi_01"}


def request(base_url: str, path: str, method: str = "GET", body: bytes | None = None, content_type: str | None = None):
    headers = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(base_url.rstrip("/") + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.headers, json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise AssertionError(f"{method} {path} returned HTTP {error.code}: {error.read().decode(errors='replace')}") from error


def multipart_demo(name: str) -> tuple[bytes, str]:
    boundary = "phishlens-demo-smoke"
    fields = {"demo": name, "no_llm": "true"}
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def main(base_url: str) -> None:
    status, _, health = request(base_url, "/health")
    assert status == 200 and health.get("status") == "ok", f"unhealthy service: {health}"

    status, _, payload = request(base_url, "/v1/demos")
    names = {item.get("name") for item in payload}
    assert status == 200 and names == DEMOS, f"unexpected demos: {sorted(names)}"

    for name in sorted(DEMOS):
        started = time.monotonic()
        body, content_type = multipart_demo(name)
        status, headers, result = request(base_url, "/v1/analyze", "POST", body, content_type)
        location = headers.get("Location")
        while status == 202 and location and time.monotonic() - started < 5:
            time.sleep(0.1)
            status, headers, result = request(base_url, urllib.parse.urlparse(location).path)
        elapsed = time.monotonic() - started
        assert status == 200, f"{name} did not complete: HTTP {status} {result}"
        assert result.get("status") == "analyzed", f"{name} status: {result}"
        assert result.get("result") is not None, f"{name} has no analysis result"
        assert elapsed <= 5, f"{name} exceeded 5 seconds: {elapsed:.3f}s"
        print(f"{name}: {result['result'].get('verdict')} in {elapsed:.3f}s")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18082")
