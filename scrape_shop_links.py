import time
import asyncio
import json
from playwright.async_api import async_playwright
from playwright_stealth import Stealth


async def run(url: str):
    async with Stealth().use_async(async_playwright()) as p:
        browser = await p.firefox.launch(
            headless=False,
            ignore_default_args=["--enable-automation"],
        )
        context = await browser.new_context()
        page = await context.new_page()

        await page.goto(url)

        start_time = time.time()
        scroll_duration = 60 * 10

        print("Scrolling started. This will take 10 minutes...")

        while True:
            elapsed_time = time.time() - start_time
            remaining_time = scroll_duration - elapsed_time

            if remaining_time <= 0:
                break

            percent_complete = (elapsed_time / scroll_duration) * 100
            elapsed_mins, elapsed_secs = divmod(int(elapsed_time), 60)
            rem_mins, rem_secs = divmod(int(remaining_time), 60)

            print(
                f"\rProgress: {percent_complete:5.1f}% | "
                f"Elapsed: {elapsed_mins:02d}:{elapsed_secs:02d} | "
                f"Time Left: {rem_mins:02d}:{rem_secs:02d}",
                end="",
                flush=True,
            )

            await page.locator("body").focus()
            await page.keyboard.press("End")
            await page.wait_for_timeout(2000)
            await page.keyboard.press("PageUp")
            await page.wait_for_timeout(300)

        print("\nScrolling complete. Saving dump...")
        with open("torob_dump.html", "w", encoding="utf-8") as f:
            f.write(await page.content())

        # Collect elements safely
        items = page.locator('a[data-testid="shop-list-item"]')
        count = await items.count()
        pages: list[str] = []

        print(f"Found {count} shop items after scrolling.")

        for i in range(count):
            try:
                # Use nth() to avoid fetching all DOM handles at once
                shop_page = await items.nth(i).get_attribute("href", timeout=5000)
                if shop_page:
                    pages.append(shop_page)
            except Exception as e:
                print(f"Error getting href for item {i}: {e}")
                continue

        # Save the collected links to a file for Step 2
        with open("shop_pages.json", "w", encoding="utf-8") as f:
            json.dump(pages, f, indent=4)

        print(f"Successfully saved {len(pages)} links to shop_pages.json")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(run("https://torob.com/shop-list"))
