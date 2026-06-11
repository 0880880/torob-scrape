import asyncio
import json
import re
import shutil
from pathlib import Path

from playwright.async_api import (
    Browser,
    BrowserContext,
    Locator,
    Page,
    Request,
    TimeoutError,
    async_playwright,
)
from playwright_stealth import Stealth

from stealth import human_click, human_type


async def extract_csrf_from_page(page: Page) -> list:
    detection_script = """
    () => {
        const tokens = [];

        // Helper to generate a precise absolute CSS selector for an element
        function getAbsoluteSelector(el) {
            if (!(el instanceof Element)) return null;
            const path = [];
            while (el.nodeType === Node.ELEMENT_NODE) {
                let selector = el.nodeName.toLowerCase();
                if (el.id) {
                    selector += '#' + el.id;
                    path.unshift(selector);
                    break; // ID is unique, stop traversing up
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

        // Patterns to match against names, IDs, and attributes
        const csrfPatterns = [
            /csrf/i, /xsrf/i, /token/i, /nonce/i, /authenticity/i, /altcha/i,
            /security/i, /_wpnonce/i, /csrfmiddlewaretoken/i, /YII_CSRF_TOKEN/i
        ];

        function matchesPatterns(str) {
            if (!str) return false;
            return csrfPatterns.some(regex => regex.test(str));
        }

        // 1. Scan <meta> tags
        const metas = document.querySelectorAll('meta');
        metas.forEach(meta => {
            const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
            const content = meta.getAttribute('content') || '';
            
            if (matchesPatterns(name) && content.length > 5) {
                tokens.push({
                    type: 'meta',
                    name: name,
                    value: content,
                    element_html: meta.outerHTML,
                    selector: getAbsoluteSelector(meta)
                });
            }
        });

        // 2. Scan <input> elements (hidden/visible fields)
        const inputs = document.querySelectorAll('input');
        inputs.forEach(input => {
            const name = input.getAttribute('name') || '';
            const id = input.getAttribute('id') || '';
            const value = input.value || '';

            if ((matchesPatterns(name) || matchesPatterns(id)) && value.length > 5) {
                tokens.push({
                    type: 'input',
                    name: name || id,
                    value: value,
                    input_type: input.getAttribute('type') || 'text',
                    element_html: input.outerHTML,
                    selector: getAbsoluteSelector(input)
                });
            }
        });

        // 3. Scan common global JS variables
        const commonGlobalKeys = [
            'csrf_token', 'csrfToken', 'CSRF_TOKEN', '_csrf', 'wp_nonce', 'securityToken'
        ];
        commonGlobalKeys.forEach(key => {
            if (window[key] && typeof window[key] === 'string') {
                tokens.push({
                    type: 'javascript_global',
                    name: key,
                    value: window[key],
                    element_html: `window.${key}`,
                    selector: 'N/A (Global JS Variable)'
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


async def process_website(
    browser: Browser,
    context: BrowserContext,
    i: int,
    url: str,
    phone_number: str,
    sms_requests: list[dict],  # Changed to store dicts instead of raw strings
    total_urls: int,
):
    async with sem:
        page = await context.new_page()

        page.on("popup", lambda popup: asyncio.create_task(popup.close()))

        captured_requests: list[dict] = []  # Changed to capture raw dicts
        is_listening = False

        await page.route(
            "**/*",
            lambda route: (
                route.abort()
                if route.request.resource_type
                in ["image", "stylesheet", "font", "media"]
                else route.continue_()
            ),
        )

        async def on_request(request: Request):
            if is_listening:
                req_data = {
                    "URL": request.url,
                    "Method": request.method,
                    "Headers": request.headers,  # Fixed: Keep headers as a dict, don't json.dumps
                }
                if request.post_data:
                    req_data["Payload"] = request.post_data
                captured_requests.append({"Type": "sms", "Request": req_data})

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

        action = await find_register_element(page)
        if action:
            await human_click(action)
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

            csrf = await extract_csrf_from_page(page)

            for step in range(3):
                await fill_preset_fields(form)

                if await phone_input.count() and await phone_input.is_visible():
                    await human_type(phone_input, f"0{phone_number}")
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

            if await has_validation_errors(form):
                raise RuntimeError("Form could not be filled")

            await page.wait_for_timeout(1000)

            found = False
            for req_dict in captured_requests:
                # Stringify dictionary temporarily to search for phone number and tokens
                req_str = json.dumps(req_dict)
                if phone_number in req_str:
                    req_str = req_str.replace(phone_number, "{{phone_number}}")
                    if len(csrf) > 0:
                        for idx, c in enumerate(csrf):
                            req_str = req_str.replace(
                                c["value"], f"{{{{csrf_token{idx}}}}}"
                            )

                    parsed = json.loads(req_str)
                    if len(csrf) > 0:
                        parsed["HasCSRF"] = True
                        parsed["CSRF"] = csrf
                        parsed["CSRFPage"] = csrf_page
                    else:
                        parsed["HasCSRF"] = False

                    # Store parsed dict directly into sms_requests list
                    sms_requests.append(parsed)
                    found = True
                    break
            if not found:
                failed.append(url)
                logs = Path("./logs")
                if logs.exists():
                    shutil.rmtree(logs)
                logs.mkdir()

                json.dump(
                    captured_requests,  # Fixed: Already a list of dicts, no need to json.loads()
                    open(
                        logs
                        / (
                            url.replace(".", "_")
                            .replace("http://", "")
                            .replace("https://", "")
                            .replace("/", "")
                            .replace("\\", "")
                            + ".txt"
                        ),
                        "w",  # Fixed: 'w' mode for writing JSON
                        encoding="utf-8",
                    ),
                    indent=4,
                )
                print("Did not find SMS endpoint skipping")

        except TimeoutError:
            failed.append(url)
            print("Timeout")
        except Exception as e:
            failed.append(url)
            print(f"Err: {e}")
        finally:
            is_listening = False
    await page.close()


async def run(phone_number: str, urls: list[str]):
    async with Stealth().use_async(async_playwright()) as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context(ignore_https_errors=True)

        sms_requests: list[dict] = []

        tasks = [
            process_website(
                browser, context, i, url, phone_number, sms_requests, len(urls)
            )
            for i, url in enumerate(urls)
        ]
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("ba bye")
        finally:
            json.dump(sms_requests, open("sms.min.json", "w", encoding="utf-8"))
            json.dump(sms_requests, open("sms.json", "w", encoding="utf-8"), indent=4)

            await browser.close()

            print(f"\nTotal captured SMS endpoints: {len(sms_requests)}")


if __name__ == "__main__":
    with open("shops.json", "r", encoding="utf-8") as f:
        urls = json.load(f)
        asyncio.run(run("9120000000", urls))
