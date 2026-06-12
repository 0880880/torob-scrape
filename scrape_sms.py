import asyncio
import base64
import contextlib
import json
import os
import re
import urllib.parse
from pathlib import Path

from playwright.async_api import (
    Locator,
    Page,
    TimeoutError,
    async_playwright,
)
from playwright_stealth import Stealth

from stealth import human_click, human_type

CSRF_KEY_RE = re.compile(
    r"csrf|xsrf|token|nonce|authenticity|_wpnonce|csrfmiddlewaretoken|yii_csrf",
    re.IGNORECASE,
)


def extract_csrf_from_request(req_data: dict) -> list:
    """Find CSRF tokens directly inside the captured request (headers + payload)."""
    found = []

    # --- Headers ---
    headers = req_data.get("Headers", {}) or {}
    for k, v in headers.items():
        if CSRF_KEY_RE.search(k) and v and len(v) > 3:
            found.append(
                {
                    "type": "request_header",
                    "name": k,
                    "value": v,
                    "selector": "N/A (Request Header)",
                }
            )

    # --- Payload ---
    payload = req_data.get("Payload")
    if payload:
        # Try JSON
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                for k, v in data.items():
                    if CSRF_KEY_RE.search(str(k)) and isinstance(v, str) and len(v) > 3:
                        found.append(
                            {
                                "type": "json_payload",
                                "name": k,
                                "value": v,
                                "selector": "N/A (JSON Body)",
                            }
                        )
        except (json.JSONDecodeError, TypeError):
            # Try urlencoded form
            try:
                parsed = urllib.parse.parse_qs(payload, keep_blank_values=True)
                for k, vals in parsed.items():
                    if CSRF_KEY_RE.search(k):
                        for v in vals:
                            if v and len(v) > 3:
                                found.append(
                                    {
                                        "type": "form_payload",
                                        "name": k,
                                        "value": v,
                                        "selector": "N/A (Form Body)",
                                    }
                                )
            except Exception:
                pass

    return found


async def extract_csrf_from_page(page: Page) -> list:
    detection_script = r"""
    () => {
        const tokens = [];

        // Mirror of the Python CSRF_KEY_RE
        const CSRF_RE = /csrf|xsrf|token|nonce|authenticity|_wpnonce|csrfmiddlewaretoken|yii_csrf/i;
        function matchesPatterns(s) {
            return typeof s === 'string' && CSRF_RE.test(s);
        }

        function getAbsoluteSelector(el) {
            if (!(el instanceof Element)) return null;
            const path = [];
            while (el && el.nodeType === Node.ELEMENT_NODE) {
                let selector = el.nodeName.toLowerCase();
                if (el.id) {
                    selector += '#' + CSS.escape(el.id);
                    path.unshift(selector);
                    break;
                } else {
                    let sib = el, nth = 1;
                    while (sib = sib.previousElementSibling) {
                        if (sib.nodeName.toLowerCase() === el.nodeName.toLowerCase()) {
                            nth++;
                        }
                    }
                    selector += `:nth-of-type(${nth})`;
                }
                path.unshift(selector);
                el = el.parentNode;
            }
            return path.join(' > ');
        }

        // 1. <meta> tags  (FIXED: this loop was broken — `const csmeta =>`)
        document.querySelectorAll('meta').forEach(meta => {
            const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
            const content = meta.getAttribute('content') || '';
            if (matchesPatterns(name) && content.length > 3) {
                tokens.push({
                    type: 'meta', name, value: content,
                    element_html: meta.outerHTML,
                    selector: getAbsoluteSelector(meta)
                });
            }
        });

        // 2. <input> elements
        document.querySelectorAll('input').forEach(input => {
            const name = input.getAttribute('name') || '';
            const id = input.getAttribute('id') || '';
            const value = input.value || '';
            if ((matchesPatterns(name) || matchesPatterns(id)) && value.length > 3) {
                tokens.push({
                    type: 'input', name: name || id, value,
                    input_type: input.getAttribute('type') || 'text',
                    element_html: input.outerHTML,
                    selector: getAbsoluteSelector(input)
                });
            }
        });

        // 3. Global JS variables
        const commonGlobalKeys = [
            'csrf_token', 'csrfToken', 'CSRF_TOKEN', '_csrf', 'wp_nonce', 'securityToken'
        ];
        commonGlobalKeys.forEach(key => {
            try {
                const val = window[key];
                if (val && typeof val === 'string' && val.length > 3) {
                    tokens.push({
                        type: 'javascript_global', name: key, value: val,
                        element_html: 'window.' + key,
                        selector: 'N/A (Global JS Variable)'
                    });
                }
            } catch (e) { /* some globals throw on access */ }
        });

        // 4. Cookies (XSRF-TOKEN etc.)
        document.cookie.split(';').forEach(c => {
            const eq = c.indexOf('=');
            const rawName = eq === -1 ? c : c.slice(0, eq);
            const rawVal  = eq === -1 ? '' : c.slice(eq + 1);
            const name = rawName.trim();
            let value = rawVal.trim();
            try { value = decodeURIComponent(value); } catch (e) { /* leave raw */ }
            if (matchesPatterns(name) && value.length > 3) {
                tokens.push({
                    type: 'cookie', name, value,
                    element_html: 'document.cookie[' + name + ']',
                    selector: 'N/A (Cookie)'
                });
            }
        });

        return tokens;
    }
    """
    try:
        return await page.evaluate(detection_script)
    except Exception as e:
        print(f"Error during token extraction: {e}")
        return []


async def find_register_element(page: Page) -> Locator | None:
    base_selector = (
        "a, button, [role='button'], input[type='button'], input[type='submit']"
    )

    search_terms = [
        r"signup",
        r"sign-up",
        r"register",
        r"login",
        r"sign in",
        r"signin",
        r"my account",
        r"profile",
        r"ثبت\s*نام",
        r"ثبت‌نام",
        r"عضویت",
        r"ورود",
        r"وارد",
        r"حساب\s*من",
        r"پروفایل",
        r"حساب\s*کاربری",
    ]

    for term in search_terms:
        regex = re.compile(term, re.IGNORECASE)
        elements = page.locator(base_selector).filter(has_text=regex)

        count = await elements.count()
        if count > 0:
            for i in range(count):
                loc = elements.nth(i)
                if await loc.is_visible():
                    return loc

    return None


async def has_validation_errors(loc: Locator) -> bool:
    native_invalid_count = await loc.locator(":invalid").count()
    if native_invalid_count > 0:
        print(f"Found {native_invalid_count} native HTML5 validation errors.")
        return True

    aria_invalid_count = await loc.locator('[aria-invalid="true"]').count()
    if aria_invalid_count > 0:
        print(f"Found {aria_invalid_count} fields marked ARIA-invalid.")
        return True

    error_texts = loc.get_by_text(
        r"required|cannot be blank|must be filled|validation failed", exact=False
    )
    if (await error_texts.count()) > 0:
        visible_errors = [el for el in (await error_texts.all()) if el.is_visible()]
        if visible_errors:
            print(f"Found {len(visible_errors)} visible validation text messages.")
            return True

    return False


async def fill_preset_fields(form: Locator):
    name_regex = re.compile(r"نام|نام خانوادگی|name|full name", re.IGNORECASE)

    text_inputs = (
        form.locator('input[type="text"]')
        .filter(has_text=name_regex)
        .or_(
            form.locator('input[type="text"][placeholder*="نام"]').or_(
                form.locator('input[type="text"][name*="name" i]')
            )
        )
    )

    count = await text_inputs.count()
    for i in range(count):
        loc = text_inputs.nth(i)
        if await loc.is_visible() and not await loc.input_value():
            await human_type(loc, "تست کاربر")


CONCURRENCY_LIMIT = 16
sem = asyncio.Semaphore(CONCURRENCY_LIMIT)


def save_live_data(sms_list: list[dict]):
    """Safely writes JSON data atomically to prevent corruption during power outages."""
    # Write formatted JSON
    with open("sms.tmp.json", "w", encoding="utf-8") as f:
        json.dump(sms_list, f, indent=4)
    os.replace("sms.tmp.json", "sms.json")

    # Write minified JSON
    with open("sms.min.tmp.json", "w", encoding="utf-8") as f:
        json.dump(sms_list, f, separators=(",", ":"))
    os.replace("sms.min.tmp.json", "sms.min.json")


async def process_website(
    browser, i, url, phone_number, sms_requests, total_urls, file_lock, processed_lock
):
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()

    async def safe_close_popup(popup):
        try:
            await popup.close()
        except Exception:
            pass

    page.on("popup", lambda popup: asyncio.create_task(safe_close_popup(popup)))

    captured_requests: list[dict] = []
    is_listening = False

    await page.route(
        "**/*",
        lambda route: (
            route.abort()
            if route.request.resource_type in ["image", "stylesheet", "font", "media"]
            else route.continue_()
        ),
    )

    async def on_request(request):
        if not is_listening:
            return
        try:
            req_data = {
                "URL": request.url,
                "Method": request.method,
                "Headers": request.headers,
            }

            raw = request.post_data_buffer
            if raw:
                try:
                    req_data["Payload"] = raw.decode("utf-8")
                except UnicodeDecodeError:
                    req_data["Payload"] = base64.b64encode(raw).decode("ascii")
                    req_data["PayloadEncoding"] = "base64"

            captured_requests.append({"Type": "sms", "Request": req_data})
        except Exception as e:
            # Never let an event handler raise — it poisons the event loop
            print(f"on_request handler error (ignored): {e!r}")

    page.on("request", on_request)

    failed: list[str] = []

    print(f'Scraping "{url}" {i + 1}/{total_urls}')
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=10000)

        try:
            body_text = await page.inner_text("body", timeout=3000)
            body_lower = body_text.lower()
            if "suspended" in body_lower or "denied" in body_lower:
                print(f"Skipping {url}: Page contains 'suspended' or 'denied'")
                failed.append(url)
                await page.close()
                return
        except Exception:
            pass

    except Exception as e:
        print(f"skipping: {e}")
        failed.append(url)
        await page.close()
        return

    phone_selectors = [
        'input[type="tel" i]',
        'input[name*="phone" i]',
        'input[name*="mobile" i]',
        'input[name*="cell" i]',
        'input[class*="phone" i]',
        'input[class*="mobile" i]',
        'input[placeholder*="تلفن"]',
        'input[placeholder*="موبایل"]',
        'input[placeholder*="09"]',
        'input[id*="username" i]',
        'input[class*="username" i]',
        'input[type="number" i]',
        'input[name="digits_reg_mobilenum"]',
        'input[name="digits_phone"]',
        'input[class*="digi-"]',
    ]

    action = await find_register_element(page)  # Make sure this helper exists
    if action:
        await human_click(action)  # Make sure this helper exists
    else:
        print(f"Could not find an account action for {url}")
        failed.append(url)
        await page.close()
        return

    try:
        pattern = re.compile(
            r"(ثبت.*نام)|(عضویت)|(ایجاد یک حساب کاربری)|(ایجاد حساب کاربری)"
        )
        register_link = page.locator("a", has_text=pattern)
        await human_click(register_link)
        await page.wait_for_selector(
            ", ".join(phone_selectors), state="visible", timeout=5000
        )
    except Exception:
        pass

    phone_input = (
        page.locator(", ".join(phone_selectors)).or_(
            page.locator(
                "xpath=//input["
                'preceding-sibling::*[contains(text(), "شماره تماس") or contains(text(), "شماره موبایل") or contains(text(), "شماره تلفن")] or '
                'following-sibling::*[contains(text(), "شماره تماس") or contains(text(), "شماره موبایل") or contains(text(), "شماره تلفن")]'
                "]"
            )
        )
    ).first

    form = phone_input.locator("xpath=./ancestor::form").first

    if not await form.count():
        form = phone_input.locator(
            "xpath=./ancestor::div[contains(@class, 'login') or contains(@class, 'register') or contains(@class, 'auth') or contains(@class, 'digits-login') or contains(@class, 'c-login') or contains(@class, 'auth-form')]"
        ).first

    if not await form.count():
        form = page.locator("html")

    submit_regex = re.compile(
        r"تایید|ورود|ادامه|ثبت|ارسال|مرحله|submit|login|continue|next|send",
        re.IGNORECASE,
    )

    button = (
        form.locator(
            'button, input[type="submit"], input[type="button"], [role="button"]'
        )
        .filter(has_text=submit_regex)
        .first
    )

    if not await button.count() or not await button.is_visible():
        button = (
            form.locator('button[type="submit"]')
            .or_(form.locator("div#login-button"))
            .first
        )

    csrf_page = page.url

    try:
        captured_requests.clear()
        is_listening = True

        csrf = await extract_csrf_from_page(page)  # Make sure this helper exists

        for step in range(3):
            await fill_preset_fields(form)  # Make sure this helper exists

            if await phone_input.count() and await phone_input.is_visible():
                await human_type(
                    phone_input, f"0{phone_number}"
                )  # Make sure this helper exists
                break

            if await button.count() and await button.is_visible():
                await human_click(button)
                await page.wait_for_timeout(1000)
            else:
                break

        await fill_preset_fields(form)

        print("Clicking the final submit button...")
        if await button.is_visible():
            await human_click(button)

        if await has_validation_errors(form):  # Make sure this helper exists
            raise RuntimeError("Form could not be filled")

        await page.wait_for_timeout(1000)

        found = False
        for req_dict in captured_requests:
            req_str = json.dumps(req_dict)
            if phone_number not in req_str:
                continue

            request_csrf = extract_csrf_from_request(
                req_dict.get("Request", {})
            )  # Make sure this helper exists

            all_tokens = {}
            for t in request_csrf + csrf:
                if t["value"] not in all_tokens:
                    all_tokens[t["value"]] = t
            merged_csrf = list(all_tokens.values())

            req_str = req_str.replace(phone_number, "{{phone_number}}")

            used_tokens = []
            for c in merged_csrf:
                val = c["value"]
                if val and val in req_str:
                    idx = len(used_tokens)
                    req_str = req_str.replace(val, f"{{{{csrf_token{idx}}}}}")
                    used_tokens.append(c)

            parsed = json.loads(req_str)

            if used_tokens:
                parsed["HasCSRF"] = True
                parsed["CSRF"] = used_tokens
                parsed["CSRFPage"] = csrf_page
            else:
                parsed["HasCSRF"] = False

            # --- NEW: Live JSON Updates safely locked ---
            async with file_lock:
                sms_requests.append(parsed)
                # Use a background thread so disk I/O doesn't block Playwright
                await asyncio.to_thread(save_live_data, sms_requests)

            print(f"[+] Found and LIVE SAVED SMS endpoint for {url}")
            found = True
            break

        if not found:
            failed.append(url)
            logs = Path("./logs")
            if (
                not logs.exists()
            ):  # Fixed logic so it doesn't delete existing logs from other tasks
                logs.mkdir(exist_ok=True)

            filename = (
                url.replace(".", "_")
                .replace("http://", "")
                .replace("https://", "")
                .replace("/", "")
                .replace("\\", "")
                + ".txt"
            )

            # FIXED: Close file automatically using 'with' block
            with open(logs / filename, "w", encoding="utf-8") as log_f:
                json.dump(captured_requests, log_f, indent=4)

            print(f"Did not find SMS endpoint for {url}, skipping")

    except TimeoutError:
        failed.append(url)
        print(f"Timeout for {url}")
    finally:
        is_listening = False
        with contextlib.suppress(Exception):
            await context.close()  # closes page + frees all buffers

    # --- NEW: Log this URL as processed so we can skip it if the script restarts ---
    async with processed_lock:

        def append_processed():
            with open("processed_urls.txt", "a", encoding="utf-8") as f:
                f.write(url + "\n")

        await asyncio.to_thread(append_processed)


BROWSER_RECYCLE_EVERY = 300

# Chromium args that matter for long, headless server runs.
CHROMIUM_ARGS = [
    "--disable-dev-shm-usage",  # avoids /dev/shm exhaustion -> sudden timeouts
    "--no-sandbox",  # needed in most Docker/root server envs
    "--disable-gpu",
    "--disable-extensions",
    "--no-first-run",
]


async def run(phone_number: str, urls: list[str]):
    file_lock = asyncio.Lock()
    processed_lock = asyncio.Lock()

    sms_requests: list[dict] = []
    processed_urls: set[str] = set()

    # --- Crash Recovery: Load existing SMS data ---
    if os.path.exists("sms.json"):
        try:
            with open("sms.json", "r", encoding="utf-8") as f:
                sms_requests = json.load(f)
            print(f"Recovered {len(sms_requests)} endpoints from previous run.")
        except json.JSONDecodeError:
            print("Warning: sms.json was corrupted. Starting fresh.")

    # --- Crash Recovery: Skip already processed URLs ---
    if os.path.exists("processed_urls.txt"):
        with open("processed_urls.txt", "r", encoding="utf-8") as f:
            processed_urls = {line.strip() for line in f if line.strip()}
        print(f"Found {len(processed_urls)} already processed URLs. Skipping them.")

    # --- Build the work queue (skip already-done URLs) ---
    queue: asyncio.Queue = asyncio.Queue()
    for i, url in enumerate(urls):
        if url not in processed_urls:
            queue.put_nowait((i, url))

    total_urls = len(urls)
    remaining = queue.qsize()
    print(f"Queued {remaining} URLs to process ({total_urls} total).")

    if remaining == 0:
        print("Nothing to do. All URLs already processed.")
        return

    # --- Browser lifecycle managed via a swappable holder ---
    # We keep the current browser in a 1-element list so workers always
    # read the latest instance after a recycle.
    browser_holder: list = [None]
    browser_lock = asyncio.Lock()  # serialize launch/relaunch
    processed_count = 0  # pages finished since last recycle
    count_lock = asyncio.Lock()

    async with Stealth().use_async(async_playwright()) as p:

        async def launch_browser():
            return await p.chromium.launch(headless=True, args=CHROMIUM_ARGS)

        async def maybe_recycle_browser():
            """Relaunch Chromium once enough pages have been processed."""
            nonlocal processed_count
            async with count_lock:
                processed_count += 1
                if processed_count < BROWSER_RECYCLE_EVERY:
                    return
                processed_count = 0  # reset before doing the (slow) swap

            # Swap the browser under the browser_lock so workers grabbing it
            # mid-recycle either get the old (still-open) or new instance.
            async with browser_lock:
                old = browser_holder[0]
                print("[*] Recycling Chromium to free memory...")
                new = await launch_browser()
                browser_holder[0] = new
                # Give in-flight pages on the old browser a moment, then close.
                if old is not None:
                    with contextlib.suppress(Exception):
                        await old.close()
                print("[*] Chromium recycled.")

        async def get_browser():
            async with browser_lock:
                return browser_holder[0]

        # Initial launch
        browser_holder[0] = await launch_browser()

        async def worker(worker_id: int):
            while True:
                try:
                    i, url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    browser = await get_browser()
                    await process_website(
                        browser,
                        i,
                        url,
                        phone_number,
                        sms_requests,
                        total_urls,
                        file_lock,
                        processed_lock,
                    )
                except asyncio.CancelledError:
                    # Re-queue so a restart can pick it up; don't mark processed.
                    raise
                except Exception as e:
                    print(f"[worker {worker_id}] Task error for {url}: {e!r}")
                finally:
                    queue.task_done()
                    await maybe_recycle_browser()

        workers = [asyncio.create_task(worker(w)) for w in range(CONCURRENCY_LIMIT)]

        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            print("\n[!] Cancellation received. Stopping workers...")
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise
        finally:
            print("\nSaving final state...")
            with contextlib.suppress(Exception):
                save_live_data(sms_requests)

            with contextlib.suppress(Exception):
                if browser_holder[0] is not None:
                    await browser_holder[0].close()

            print(f"\nTotal captured SMS endpoints: {len(sms_requests)}")


if __name__ == "__main__":
    try:
        with open("shops.json", "r", encoding="utf-8") as f:
            urls = json.load(f)

        # Using asyncio.run inside a try-except to catch Ctrl+C safely at the top level
        asyncio.run(run("9120000000", urls))

    except KeyboardInterrupt:
        print("\n[!] Scraper stopped by user (Ctrl+C). Live progress was saved safely.")
