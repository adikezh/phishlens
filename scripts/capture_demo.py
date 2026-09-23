"""Capture the rendered landing page and a real demo verdict as an animated GIF.

Run against a started server, for example:
    python scripts/capture_demo.py http://127.0.0.1:8082 docs/assets/phishlens-demo.gif
"""

import io
import sys
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright


def main(base_url: str, output: str) -> None:
    frames = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        page.goto(base_url.rstrip("/") + "/landing")
        page.wait_for_load_state("networkidle")
        frames.append(Image.open(io.BytesIO(page.screenshot(full_page=True))).convert("RGB"))

        page.goto(base_url.rstrip("/") + "/")
        page.wait_for_load_state("networkidle")
        page.get_by_role("button", name="Фишинг «Kaspi»: подмена отправителя и ссылки").click()
        page.locator("#result").get_by_text("Фишинг", exact=False).wait_for()
        frames.append(Image.open(io.BytesIO(page.screenshot(full_page=True))).convert("RGB"))
        browser.close()

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(destination, save_all=True, append_images=frames[1:], duration=1800, loop=0, disposal=2)
    print(f"captured {len(frames)} frames to {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: capture_demo.py BASE_URL OUTPUT_GIF")
    main(sys.argv[1], sys.argv[2])
