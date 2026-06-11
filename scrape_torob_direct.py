import asyncio
import json

import httpx


def get_torob_url(page: int, size: int) -> str:
    return f"https://api.torob.com/v4/internet-shop/list/?page={page}&shop_type=all&size={size}&source=next_desktop&_landing_page=shop-list"


def build_requests(amount: int, buffer_size: int) -> list[tuple[int, int]]:
    """Return a list of (page, size) pairs covering `amount` shops."""
    requests: list[tuple[int, int]] = []
    page = 1
    while amount > 0:
        size = min(buffer_size, amount)
        requests.append((page, size))
        amount -= size
        page += 1
    return requests


async def fetch_page(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    page: int,
    size: int,
    max_retries: int = 5,
    base_delay: float = 1.0,
) -> list[str]:
    async with sem:
        for attempt in range(1, max_retries + 1):
            try:
                resp = await client.get(get_torob_url(page, size))
                resp.raise_for_status()
                data = resp.json()
                print(f"Page {page:03}")
                return ["https://" + shop["domain"] for shop in data["results"]]
            except (httpx.HTTPError, json.JSONDecodeError) as e:
                if attempt == max_retries:
                    print(f"Page {page:03} FAILED after {max_retries} attempts: {e}")
                    raise
                delay = base_delay * (2 ** (attempt - 1))
                print(
                    f"Page {page:03} attempt {attempt} failed ({e}); "
                    f"retrying in {delay:.1f}s"
                )
                await asyncio.sleep(delay)

    # Unreachable, but keeps type checkers happy
    return []


async def main() -> None:
    amount = int(input("How many shops to scrape: "))
    buffer_size = int(input("Buffer size: "))

    requests = build_requests(amount, buffer_size)
    sem = asyncio.Semaphore(10)  # max 10 concurrent requests

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *(fetch_page(client, sem, page, size) for page, size in requests)
        )

    shops: list[str] = [url for page_shops in results for url in page_shops]

    with open("shops.json", "w", encoding="utf-8") as f:
        json.dump(shops, f)


if __name__ == "__main__":
    asyncio.run(main())
