"""Black-box smoke test for the operator UI against a started PhishLens server."""

import sys
import argparse
from playwright.sync_api import sync_playwright


def api_e2e(request, base_url: str, admin_key: str, user_key: str) -> None:
    def call(method: str, path: str, key: str, **kwargs):
        response = request.fetch(
            base_url + path,
            method=method,
            headers={"Authorization": "Bearer " + key, "X-API-Key": key},
            **kwargs,
        )
        return response

    body = {"text": "From: billing@example.test\nSubject: Review\n\nPlease review https://example.test", "lang": "en"}
    created = call("POST", "/v1/analyze", user_key, data=body)
    assert created.ok, f"analyze failed: {created.status} {created.text()}"
    submission_id = created.json()["id"]

    retrieved = call("GET", "/v1/analyses/" + submission_id, user_key)
    assert retrieved.ok and retrieved.json()["id"] == submission_id

    forbidden = call("GET", "/v1/submissions", user_key)
    assert forbidden.status == 403, f"user queue access returned {forbidden.status}"
    allowed = call("GET", "/v1/submissions", admin_key)
    assert allowed.ok, f"admin queue access failed: {allowed.status}"

    deleted = call("DELETE", "/v1/submissions/" + submission_id, admin_key)
    assert deleted.status == 204, f"delete returned {deleted.status}"
    missing = call("GET", "/v1/analyses/" + submission_id, admin_key)
    assert missing.status == 404, f"deleted analysis returned {missing.status}"


def main(base_url: str, admin_key: str | None = None, user_key: str | None = None) -> None:
    console_errors = []
    with sync_playwright() as playwright:
        if admin_key and user_key:
            request = playwright.request.new_context()
            try:
                api_e2e(request, base_url, admin_key, user_key)
            finally:
                request.dispose()

        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)

        page.goto(base_url + "/ui/queue")
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="Очередь ИБ").is_visible()
        assert page.get_by_text("Введите API-ключ с ролью analyst или admin.").is_visible()
        assert page.get_by_role("link", name="Кампании").is_visible()

        page.goto(base_url + "/ui/brands")
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="Бренды").is_visible()
        assert page.get_by_text("Справочник брендов").is_visible()
        assert page.get_by_text("105 записей").is_visible()

        page.goto(base_url + "/ui/dashboard")
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="Дашборд").is_visible()
        assert page.get_by_text("Введите API-ключ с ролью analyst или admin.").is_visible()

        if admin_key:
            page.goto(base_url + "/ui/queue")
            page.get_by_label("API-ключ аналитика/admin").fill(admin_key)
            page.get_by_role("button", name="Сохранить ключ").click()
            page.get_by_role("button", name="Загрузить очередь").click()
            page.wait_for_function("document.querySelector('#operator-state').textContent.includes('Очередь') || document.querySelector('#operator-state').textContent.includes('Показано')")
            assert "HTTP 401" not in page.locator("#operator-state").inner_text()

        browser.close()
    if console_errors:
        raise AssertionError("browser console errors: " + "; ".join(console_errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url", nargs="?", default="http://127.0.0.1:18082")
    parser.add_argument("--admin-key")
    parser.add_argument("--user-key")
    args = parser.parse_args()
    if bool(args.admin_key) != bool(args.user_key):
        parser.error("--admin-key and --user-key must be supplied together")
    main(args.base_url, args.admin_key, args.user_key)
