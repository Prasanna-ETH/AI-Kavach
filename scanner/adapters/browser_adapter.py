"""Playwright Browser Adapter for AI-powered Web Forms & Frontend Chat Interfaces.

Enables automated security scanning directly against web applications, chat widgets,
PortSwigger labs, and browser forms via headless Chromium.

NOTE: Uses the *synchronous* Playwright API run inside asyncio.to_thread() to work
around the Windows ProactorEventLoop NotImplementedError that the async API raises
when uvicorn is the ASGI server (it cannot spawn subprocesses from within the
running event loop on Windows).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Set

from scanner.adapters.base import BaseAdapter

logger = logging.getLogger("scanner.adapter.browser")

DEFAULT_INPUT_SELECTOR = (
    "textarea, "
    "input[name='message'], "
    "input[name='prompt'], "
    "input[name='chat'], "
    "input[placeholder*='message' i], "
    "input[placeholder*='ask' i], "
    "input[placeholder*='type' i], "
    "input[placeholder*='chat' i], "
    "input#chat-input, "
    "input.chat-input, "
    "input[type='text']:not(#flagInput):not([placeholder*='flag' i]):not([placeholder*='ctf' i])"
)
DEFAULT_SUBMIT_SELECTOR = "button[type='submit'], button#send, button.send, input[type='submit']"
DEFAULT_RESPONSE_SELECTOR = (
    "table tr:last-child td, "
    "tr:has(th:has-text('Arti')) td, "
    "tr:has(th:has-text('Assistant')) td, "
    "tr:has(th:has-text('Bot')) td, "
    ".message.assistant, .bot-message, .chat-response, .ai-response, "
    "div[data-role='assistant'], #chat-response, .response"
)


def compute_delta_text(before_text: str, after_text: str, sent_prompt: str = "") -> str:
    """Extract ONLY newly added text by computing the mathematical delta between page snapshots.

    Discards any static headers, footers, website contact emails, and prompt echoes that existed
    before the prompt was submitted.
    """
    if not after_text:
        return ""
    if not before_text:
        return isolate_assistant_response(after_text, sent_prompt)

    before_lines: Set[str] = {line.strip() for line in before_text.splitlines() if line.strip()}
    
    if sent_prompt:
        for p_line in sent_prompt.splitlines():
            if p_line.strip():
                before_lines.add(p_line.strip())

    after_lines = after_text.splitlines()
    new_lines: List[str] = []

    for line in after_lines:
        clean_l = line.strip()
        if not clean_l:
            continue
        if clean_l not in before_lines:
            new_lines.append(clean_l)

    delta_result = "\n".join(new_lines).strip()
    if delta_result:
        return isolate_assistant_response(delta_result, sent_prompt)

    return isolate_assistant_response(after_text, sent_prompt)


def isolate_assistant_response(raw_text: str, sent_prompt: str = "") -> str:
    """Isolate the assistant's reply from a full chat transcript or scraped webpage DOM."""
    if not raw_text:
        return ""

    text = raw_text.strip()

    # 1. Strip known challenge & website boilerplate
    boilerplate_patterns = [
        r"^.*?(?:CONNECTED:\s*--\s*Now\s+chatting\s+with\s+[\w\s]+--)",
        r"(?:SHARE\s+THIS\s+CHALLENGE\s+WITH\s+YOUR\s+NETWORK.*)$",
        r"(?:With\s+❤️\s+by\s+@\w+.*)$",
        r"(?:Found\s+an\s+issue\s+or\s+need\s+help\?\s*Email\s+us\s+at\s+[\w\.\@\-]+.*)$",
        r"(?:We\s+only\s+use\s+cookies\s+that\s+are\s+strictly\s+necessary.*)$",
        r"(?:Terms\s+of\s+Service.*)$",
        r"(?:Privacy\s+Policy.*)$",
        r"(?:Your\s+message:\s*Send.*)$",
        r"(?:Back\s+to\s+lab\s+description.*)$",
    ]
    for b_pat in boilerplate_patterns:
        text = re.sub(b_pat, "", text, flags=re.IGNORECASE | re.DOTALL).strip()

    # 2. Check for standard Chat role prefixes
    assistant_markers = [
        r"(?:^|\n)(?:Arti\s+Ficial|Assistant|Bot|AI|Model|System):\s*[\t]?",
    ]

    last_assistant_pos = -1
    for marker in assistant_markers:
        matches = list(re.finditer(marker, text, re.IGNORECASE))
        if matches:
            last_match = matches[-1]
            if last_match.end() > last_assistant_pos:
                last_assistant_pos = last_match.end()

    if last_assistant_pos != -1:
        isolated = text[last_assistant_pos:].strip()
        cutoff_markers = [
            r"(?:^|\n)(?:You|User|Human):\s*",
            r"(?:^|\n)(?:Your\s+message:|Send\s*$)",
            r"(?:^|\n)Back\s+to\s+lab\s+description",
        ]
        min_cutoff = len(isolated)
        for c_marker in cutoff_markers:
            c_match = re.search(c_marker, isolated, re.IGNORECASE)
            if c_match and c_match.start() < min_cutoff:
                min_cutoff = c_match.start()

        extracted = isolated[:min_cutoff].strip()
        if extracted:
            return extracted

    # 3. Robust Whitespace-Agnostic Prompt Echo Stripping
    if sent_prompt:
        clean_prompt = sent_prompt.strip()
        if clean_prompt in text:
            after_prompt = text.split(clean_prompt, 1)[-1].strip()
            after_prompt = re.sub(
                r"^(?:You|User|Human|Arti\s+Ficial|Assistant|Bot|AI|Model)?\s*[:\t\n\-]+\s*",
                "",
                after_prompt,
                flags=re.IGNORECASE,
            ).strip()
            if after_prompt:
                return after_prompt

        prompt_words = [re.escape(w) for w in re.split(r"\s+", clean_prompt) if w]
        if prompt_words:
            flexible_prompt_pat = r"\s+".join(prompt_words)
            p_match = re.search(flexible_prompt_pat, text, flags=re.IGNORECASE)
            if p_match:
                after_prompt = text[p_match.end():].strip()
                after_prompt = re.sub(
                    r"^(?:You|User|Human|Arti\s+Ficial|Assistant|Bot|AI|Model)?\s*[:\t\n\-]+\s*",
                    "",
                    after_prompt,
                    flags=re.IGNORECASE,
                ).strip()
                if after_prompt:
                    return after_prompt

    return text


# ---------------------------------------------------------------------------
# Sync helpers — run by sync_playwright inside worker threads
# ---------------------------------------------------------------------------

def _sync_validate_selectors(
    target_url: str,
    input_selector: str,
    send_button_selector: str,
    response_selector: str,
    wait_ms: int,
    login_config: Optional[Dict[str, str]],
    headless: bool,
    auth_header: Optional[str] = None,
) -> Dict[str, Any]:
    """Synchronous validate_selectors — runs inside a thread via asyncio.to_thread()."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ImportError(
            "Playwright package is not installed. "
            "Install it using: uv add playwright && uv run playwright install chromium"
        )

    results: Dict[str, Any] = {
        "ok": True,
        "url": target_url,
        "selectors": {},
        "error": None,
    }

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        try:
            context = browser.new_context()
            if auth_header and auth_header.strip():
                ah = auth_header.strip()
                if ":" in ah:
                    hk, hv = ah.split(":", 1)
                    context.set_extra_http_headers({hk.strip(): hv.strip()})
                else:
                    context.set_extra_http_headers({"Authorization": ah})
            page = context.new_page()

            logger.info(f"Validating selectors against: {target_url}")
            page.goto(target_url, timeout=wait_ms, wait_until="domcontentloaded")

            # Optional login form validation
            if login_config:
                u_sel = login_config.get("username_selector", "")
                p_sel = login_config.get("password_selector", "")
                btn_sel = login_config.get("login_button_selector", "")

                if u_sel:
                    u_found = page.query_selector(u_sel)
                    results["selectors"]["username_selector"] = {
                        "selector": u_sel,
                        "found": bool(u_found),
                        "visible": u_found.is_visible() if u_found else False,
                    }
                    if not u_found:
                        results["ok"] = False

                if p_sel:
                    p_found = page.query_selector(p_sel)
                    results["selectors"]["password_selector"] = {
                        "selector": p_sel,
                        "found": bool(p_found),
                        "visible": p_found.is_visible() if p_found else False,
                    }
                    if not p_found:
                        results["ok"] = False

                if btn_sel:
                    btn_found = page.query_selector(btn_sel)
                    results["selectors"]["login_button_selector"] = {
                        "selector": btn_sel,
                        "found": bool(btn_found),
                        "visible": btn_found.is_visible() if btn_found else False,
                    }

                # Perform login so chat selectors can be checked on post-login page
                _sync_perform_login(page, login_config, wait_ms)

            # 1. Validate Input Selector
            input_matches = page.query_selector_all(input_selector)
            input_found = len(input_matches) > 0
            input_visible = any(
                _safe_is_visible(e) for e in input_matches
            )
            results["selectors"]["input_selector"] = {
                "selector": input_selector,
                "found": input_found,
                "visible": input_visible,
                "count": len(input_matches),
            }
            if not input_found or not input_visible:
                results["ok"] = False
                if not input_found:
                    results["error"] = (
                        f"Chat input selector '{input_selector}' did not match any elements on the page."
                    )
                else:
                    results["error"] = (
                        f"Chat input selector '{input_selector}' matched {len(input_matches)} element(s) but none were visible."
                    )

            # 2. Validate Send Button Selector
            btn_matches = page.query_selector_all(send_button_selector)
            btn_found = len(btn_matches) > 0
            btn_visible = any(_safe_is_visible(e) for e in btn_matches)
            results["selectors"]["send_button_selector"] = {
                "selector": send_button_selector,
                "found": btn_found,
                "visible": btn_visible,
                "count": len(btn_matches),
                "note": "Optional if input submits on Enter key" if not btn_found else None,
            }

            # 3. Validate Response Selector (syntax + count)
            try:
                resp_matches = page.query_selector_all(response_selector)
                results["selectors"]["response_selector"] = {
                    "selector": response_selector,
                    "found": True,
                    "count": len(resp_matches),
                    "note": (
                        f"Valid CSS selector. (Currently {len(resp_matches)} matching element(s) in DOM before messages sent)"
                    ),
                }
            except Exception as sel_err:
                results["selectors"]["response_selector"] = {
                    "selector": response_selector,
                    "found": False,
                    "count": 0,
                    "error": str(sel_err),
                }
                results["ok"] = False
                results["error"] = f"Invalid response CSS selector syntax: '{response_selector}'"

        except Exception as err:
            logger.error(f"Selector validation failed: {err}")
            results["ok"] = False
            results["error"] = f"Page navigation/validation error on '{target_url}': {err}"
        finally:
            browser.close()
            logger.info("Playwright browser closed.")

    return results


def _sync_send(
    target_url: str,
    prompt: str,
    input_selector: str,
    send_button_selector: str,
    response_selector: str,
    wait_ms: int,
    login_config: Optional[Dict[str, str]],
    headless: bool,
    logged_in_flag: list,  # mutable flag shared for login state [bool]
    auth_header: Optional[str] = None,
) -> str:
    """Synchronous send — runs inside a thread via asyncio.to_thread()."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ImportError(
            "Playwright package is not installed. "
            "Install it using: uv add playwright && uv run playwright install chromium"
        )

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        try:
            context = browser.new_context()
            if auth_header and auth_header.strip():
                ah = auth_header.strip()
                if ":" in ah:
                    hk, hv = ah.split(":", 1)
                    context.set_extra_http_headers({hk.strip(): hv.strip()})
                else:
                    context.set_extra_http_headers({"Authorization": ah})
            page = context.new_page()

            # Capture JSON responses from network for API-based targets
            intercepted_responses: List[str] = []

            def _on_response(resp):
                try:
                    if resp.request.method in ("POST", "GET") and any(
                        k in resp.url.lower()
                        for k in ["/chat", "/api", "/generate", "/message", "/completion", "/v1/"]
                    ):
                        ct = resp.headers.get("content-type", "").lower()
                        if "json" in ct:
                            data = resp.json()
                            if isinstance(data, dict):
                                for key in ["reply", "response", "message", "content", "output", "text"]:
                                    if key in data:
                                        val = data[key]
                                        if isinstance(val, str) and val.strip():
                                            intercepted_responses.append(val.strip())
                                        elif isinstance(val, dict) and "content" in val:
                                            intercepted_responses.append(str(val["content"]).strip())
                except Exception:
                    pass

            page.on("response", _on_response)

            logger.info(f"Navigating to {target_url}...")
            page.goto(target_url, timeout=wait_ms, wait_until="domcontentloaded")

            # Optional login
            if login_config and not logged_in_flag[0]:
                _sync_perform_login(page, login_config, wait_ms)
                logged_in_flag[0] = True

            # Snapshot before submitting
            before_body = page.query_selector("body")
            before_text = before_body.inner_text().strip() if before_body else ""

            # Locate input element
            logger.info(f"Locating input selector: '{input_selector}'")
            candidates = page.query_selector_all(input_selector)
            input_elem = None
            for c in candidates:
                try:
                    if _safe_is_visible(c):
                        c_id = (c.get_attribute("id") or "").lower()
                        c_ph = (c.get_attribute("placeholder") or "").lower()
                        if "flag" in c_id or "ctf" in c_ph or "flag" in c_ph:
                            continue
                        input_elem = c
                        break
                except Exception:
                    continue

            if not input_elem:
                input_elem = page.wait_for_selector(input_selector, timeout=wait_ms)
            if not input_elem:
                raise ValueError(f"Input element not found: '{input_selector}'")

            input_elem.fill(prompt)

            # Count existing responses before submit
            prev_responses = page.query_selector_all(response_selector)
            prev_count = len(prev_responses)
            prev_texts = [_safe_inner_text(e) for e in prev_responses]

            # Submit
            submit_btn = page.query_selector(send_button_selector)
            if submit_btn and _safe_is_visible(submit_btn):
                logger.info(f"Clicking submit button: '{send_button_selector}'")
                submit_btn.click()
            else:
                logger.info("Pressing Enter to submit prompt...")
                input_elem.press("Enter")

            # Poll for new response
            loading_placeholders = {
                "typing...", "typing", "thinking...", "thinking",
                "loading...", "loading", "generating..."
            }
            interval_ms = 400
            elapsed = 0
            extracted_text = ""

            while elapsed < wait_ms:
                import time as _time
                _time.sleep(interval_ms / 1000)
                elapsed += interval_ms

                if intercepted_responses:
                    extracted_text = intercepted_responses[-1]
                    logger.info(f"Captured via network interception ({len(extracted_text)} chars)")
                    break

                current_responses = page.query_selector_all(response_selector)
                if len(current_responses) > prev_count:
                    latest_elem = current_responses[-1]
                    candidate_text = _safe_inner_text(latest_elem)
                    if candidate_text and candidate_text.lower() not in loading_placeholders:
                        extracted_text = candidate_text
                        break
                elif len(current_responses) == prev_count and prev_count > 0:
                    current_text = _safe_inner_text(current_responses[-1])
                    if (
                        current_text
                        and current_text != prev_texts[-1]
                        and current_text.lower() not in loading_placeholders
                    ):
                        extracted_text = current_text
                        break

            # Fallback: snapshot delta diffing
            if not extracted_text or extracted_text.lower() in {
                "typing...", "typing", "thinking...", "loading..."
            }:
                after_body = page.query_selector("body")
                after_text = after_body.inner_text().strip() if after_body else ""
                diffed = compute_delta_text(before_text, after_text, sent_prompt=prompt)
                if diffed and diffed.lower() not in {"typing...", "typing", "thinking...", "loading..."}:
                    extracted_text = diffed

            isolated = isolate_assistant_response(extracted_text, sent_prompt=prompt)
            logger.info(f"Extracted isolated response ({len(isolated)} chars): {isolated[:90]!r}...")
            return isolated

        except Exception as err:
            logger.error(f"Browser interaction error on {target_url}: {err}")
            raise
        finally:
            browser.close()
            logger.info("Playwright browser closed.")


def _sync_perform_login(page, login_config: Dict[str, str], wait_ms: int) -> None:
    """Perform sync login flow in the current page."""
    u_sel = login_config.get("username_selector", "")
    u_val = login_config.get("username_value", "")
    p_sel = login_config.get("password_selector", "")
    p_val = login_config.get("password_value", "")
    btn_sel = login_config.get("login_button_selector", "")

    if not u_sel or not p_sel:
        return

    try:
        logger.info("Executing automated login flow...")
        u_elem = page.wait_for_selector(u_sel, timeout=wait_ms)
        if u_elem:
            u_elem.fill(u_val)

        p_elem = page.wait_for_selector(p_sel, timeout=wait_ms)
        if p_elem:
            p_elem.fill(p_val)

        if btn_sel:
            btn_elem = page.wait_for_selector(btn_sel, timeout=wait_ms)
            if btn_elem:
                btn_elem.click()
        elif p_elem:
            p_elem.press("Enter")

        try:
            page.wait_for_load_state("domcontentloaded", timeout=wait_ms)
        except Exception:
            pass

        logger.info("Login flow completed.")
    except Exception as err:
        logger.warning(f"Login flow error (continuing): {err}")


def _safe_is_visible(elem) -> bool:
    try:
        return elem.is_visible()
    except Exception:
        return False


def _safe_inner_text(elem) -> str:
    try:
        return elem.inner_text().strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public Async BrowserAdapter — wraps sync helpers in to_thread()
# ---------------------------------------------------------------------------

class BrowserAdapter(BaseAdapter):
    """Playwright Browser Adapter.

    Runs headless Chromium via the *synchronous* Playwright API inside
    asyncio.to_thread() to avoid the Windows ProactorEventLoop
    NotImplementedError that the async Playwright API encounters when
    hosted inside uvicorn.
    """

    def __init__(
        self,
        target_url: str = "",
        input_selector: str = DEFAULT_INPUT_SELECTOR,
        send_button_selector: str = DEFAULT_SUBMIT_SELECTOR,
        response_selector: str = DEFAULT_RESPONSE_SELECTOR,
        wait_for_response_timeout: float = 10.0,
        login_config: Optional[Dict[str, str]] = None,
        headless: bool = True,
        auth_header: Optional[str] = None,
        # Backward compatibility aliases:
        url: Optional[str] = None,
        submit_selector: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.target_url = target_url or url or ""
        self.url = self.target_url
        self.input_selector = input_selector or DEFAULT_INPUT_SELECTOR
        self.send_button_selector = submit_selector or send_button_selector or DEFAULT_SUBMIT_SELECTOR
        self.submit_selector = self.send_button_selector
        self.response_selector = response_selector or DEFAULT_RESPONSE_SELECTOR
        self.wait_for_response_timeout = timeout if timeout is not None else wait_for_response_timeout
        self.timeout = self.wait_for_response_timeout
        self.login_config = login_config
        self.headless = headless
        self.auth_header = auth_header
        self._logged_in_flag = [False]  # mutable flag for login state across send() calls

        # Kept for API compatibility with old async tests that set these directly
        self._browser = None
        self._context = None
        self._playwright = None

    @property
    def _wait_ms(self) -> int:
        return int(self.wait_for_response_timeout * 1000)

    async def close(self) -> None:
        """No persistent browser to close — each send/validate opens and closes its own instance."""
        pass

    async def validate_selectors(self) -> Dict[str, Any]:
        """Health-check method to validate selectors resolve to real elements on the target page.

        Runs synchronous Playwright in a thread to avoid Windows event loop subprocess issues.
        """
        if not self.target_url:
            return {
                "ok": False,
                "url": "",
                "selectors": {},
                "error": "Target URL is required for validation.",
            }

        return await asyncio.to_thread(
            _sync_validate_selectors,
            self.target_url,
            self.input_selector,
            self.send_button_selector,
            self.response_selector,
            self._wait_ms,
            self.login_config,
            self.headless,
            self.auth_header,
        )

    async def send(self, prompt: str) -> str:
        """Submit prompt to web form and extract assistant response.

        Runs synchronous Playwright in a thread to avoid Windows event loop subprocess issues.
        """
        return await asyncio.to_thread(
            _sync_send,
            self.target_url,
            prompt,
            self.input_selector,
            self.send_button_selector,
            self.response_selector,
            self._wait_ms,
            self.login_config,
            self.headless,
            self._logged_in_flag,
            self.auth_header,
        )


# Alias for backward compatibility
PlaywrightAdapter = BrowserAdapter
