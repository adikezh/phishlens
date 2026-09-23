"""Black-box smoke test for the operator UI against a started PhishLens server."""

import sys
from playwright.sync_api import sync_playwright


def main(base_url: str) -> None:
    console_errors = []
    with sync_playwright() as playwright:
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

        browser.close()
    if console_errors:
        raise AssertionError("browser console errors: " + "; ".join(console_errors))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18082")
