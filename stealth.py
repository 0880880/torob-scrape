from playwright.async_api import Locator, Page
import asyncio
import random


async def human_type(locator: Locator, text: str):
    await locator.focus()
    for char in text:
        await locator.type(char)
        await asyncio.sleep(random.uniform(0.05, 0.15))


async def human_click(locator: Locator):
    box = await locator.bounding_box()

    if box:
        # Calculate random point inside the button using the formula:
        # $x = box["x"] + box["width"] \times \text{random}(0.3, 0.7)$
        # $y = box["y"] + box["height"] \times \text{random}(0.3, 0.7)$
        x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
        y = box["y"] + box["height"] * random.uniform(0.3, 0.7)

        page = locator.page

        await page.mouse.move(x, y, steps=10)
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await page.mouse.click(x, y)


async def scroll_bottom(
    page: Page, step: int = 150, delay: float = 0.1, max_scrolls: int = 100
):
    """
    Scrolls down the page naturally to trigger lazy loading.

    :param page: Playwright Page instance
    :param step: Number of pixels to scroll in each step
    :param delay: Time in seconds to wait between scroll steps
    :param max_scrolls: Safeguard limit to prevent infinite loops on truly infinite scroll pages
    """
    scroll_count = 0

    while scroll_count < max_scrolls:
        # Scroll down by the step amount
        await page.evaluate(f"window.scrollBy(0, {step})")
        await asyncio.sleep(delay)

        # Check current position
        current_position = await page.evaluate(
            "window.pageYOffset + window.innerHeight"
        )
        new_height = await page.evaluate("document.body.scrollHeight")

        # If we reached the bottom of the page
        if current_position >= new_height:
            # Wait a moment to see if new content loaded and increased the height
            await asyncio.sleep(1.0)
            new_height = await page.evaluate("document.body.scrollHeight")

            # If the height didn't change, we are officially at the bottom
            if current_position >= new_height:
                break

        scroll_count += 1
