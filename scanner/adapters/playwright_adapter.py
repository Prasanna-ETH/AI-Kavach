"""Playwright Browser Adapter for AI-powered Web Forms & Frontend Chat Interfaces."""

import asyncio
import logging
import re
from typing import List, Optional, Set
from scanner.adapters.base import BaseAdapter

logger = logging.getLogger("scanner.adapter.playwright")

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

    Args:
        before_text: Raw body text before sending prompt.
        after_text: Raw body text after model response rendered.
        sent_prompt: The prompt text sent by the scanner.

    Returns:
        Newly generated assistant text string.
    """
    if not after_text:
        return ""
    if not before_text:
        return isolate_assistant_response(after_text, sent_prompt)

    # Build set of lines that existed before submission
    before_lines: Set[str] = {line.strip() for line in before_text.splitlines() if line.strip()}
    
    # Also ignore lines belonging to the user's prompt
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
        # If line did not exist prior to prompt submission, it is new output
        if clean_l not in before_lines:
            new_lines.append(clean_l)

    delta_result = "\n".join(new_lines).strip()
    if delta_result:
        return isolate_assistant_response(delta_result, sent_prompt)

    return isolate_assistant_response(after_text, sent_prompt)


def isolate_assistant_response(raw_text: str, sent_prompt: str = "") -> str:
    """Isolate the assistant's reply from a full chat transcript or scraped webpage DOM.

    Removes user message echoes ('You: ...', 'User: ...'), prompt reflections,
    PortSwigger connectivity headers, Wiz CTF challenge boilerplate, and form action buttons.

    Args:
        raw_text: Full raw text scraped from DOM or chat container.
        sent_prompt: The original prompt sent by the scanner.

    Returns:
        Cleaned assistant reply string.
    """
    if not raw_text:
        return ""

    text = raw_text.strip()

    # 1. Strip known challenge & website boilerplate (Prompt Airlines, PortSwigger, CTFs)
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

    # 2. Check for standard Chat role prefixes (e.g. 'Arti Ficial:', 'Assistant:', 'AI:', 'Bot:', 'Model:')
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
        # Direct exact match check
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

        # Whitespace-collapsed HTML regex match (handles newlines collapsed into spaces)
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


class PlaywrightAdapter(BaseAdapter):
    """Interacts with browser-rendered LLM chat interfaces, PortSwigger labs, and AI web forms.

    Automatically handles cookies, CSRF tokens, session state, and JavaScript execution
    by typing prompts directly into the DOM input field, intercepting network API responses,
    and performing Snapshot Delta Diffing to eliminate webpage footer and header noise.
    """

    def __init__(
        self,
        url: str,
        input_selector: str = DEFAULT_INPUT_SELECTOR,
        submit_selector: str = DEFAULT_SUBMIT_SELECTOR,
        response_selector: str = DEFAULT_RESPONSE_SELECTOR,
        headless: bool = True,
        timeout: float = 30.0,
    ) -> None:
        """Initialize PlaywrightAdapter.

        Args:
            url: Target web page URL containing the chat UI or AI form.
            input_selector: CSS selector for the chat input textbox.
            submit_selector: CSS selector for the Send/Submit button.
            response_selector: CSS selector for the assistant's rendered reply container.
            headless: Whether to run Chromium in headless mode (default True).
            timeout: Page navigation and element timeout in seconds (default 30.0s).
        """
        self.url = url
        self.input_selector = input_selector
        self.submit_selector = submit_selector
        self.response_selector = response_selector
        self.headless = headless
        self.timeout = timeout
        self._browser = None
        self._context = None
        self._playwright = None

    async def _init_browser(self):
        """Lazy-initialize Playwright browser instance."""
        if self._browser is not None:
            return

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)
            self._context = await self._browser.new_context()
            logger.info(f"Playwright Chromium browser initialized (headless={self.headless})")
        except ImportError:
            raise ImportError(
                "Playwright package is not installed. "
                "Install it using: uv add playwright && uv run playwright install chromium"
            )
        except Exception as err:
            logger.error(f"Failed to launch Playwright browser: {err}")
            raise

    async def close(self) -> None:
        """Close browser context and stop Playwright process."""
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        logger.info("Playwright browser closed.")

    async def send(self, prompt: str) -> str:
        """Type prompt into web form, submit, and extract assistant response.

        Args:
            prompt: Attack payload text to send.

        Returns:
            Extracted and isolated text response from the assistant.
        """
        await self._init_browser()
        page = await self._context.new_page()

        # Network response interception buffer
        intercepted_responses: List[str] = []

        async def _on_response(resp):
            try:
                req = resp.request
                # Intercept JSON API calls related to chat/generate
                if req.method in ("POST", "GET") and any(k in resp.url.lower() for k in ["/chat", "/api", "/generate", "/message", "/completion", "/v1/"]):
                    ct = resp.headers.get("content-type", "").lower()
                    if "json" in ct:
                        data = await resp.json()
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

        try:
            logger.info(f"Navigating to {self.url}...")
            await page.goto(self.url, timeout=int(self.timeout * 1000), wait_until="domcontentloaded")

            # Snapshot 1: Take page text BEFORE sending prompt (for Delta Diffing)
            before_body = await page.query_selector("body")
            before_text = (await before_body.inner_text()).strip() if before_body else ""

            # 1. Locate and fill input field
            logger.info(f"Locating input selector: '{self.input_selector}'")
            candidates = await page.query_selector_all(self.input_selector)
            input_elem = None
            for c in candidates:
                try:
                    if await c.is_visible():
                        c_id_val = await c.get_attribute("id")
                        c_id = (c_id_val or "").lower()
                        c_ph_val = await c.get_attribute("placeholder")
                        c_ph = (c_ph_val or "").lower()
                        if "flag" in c_id or "ctf" in c_ph or "flag" in c_ph:
                            continue
                        input_elem = c
                        break
                except Exception:
                    continue

            if not input_elem:
                input_elem = await page.wait_for_selector(self.input_selector, timeout=int(self.timeout * 1000))
            if not input_elem:
                raise ValueError(f"Input element not found matching selector: '{self.input_selector}'")

            await input_elem.fill(prompt)

            # 2. Count existing response elements before submitting
            prev_responses = await page.query_selector_all(self.response_selector)
            prev_count = len(prev_responses)

            # 3. Submit form (click button or press Enter)
            submit_btn = await page.query_selector(self.submit_selector)
            if submit_btn and await submit_btn.is_visible():
                logger.info(f"Clicking submit button: '{self.submit_selector}'")
                await submit_btn.click()
            else:
                logger.info("Pressing Enter to submit prompt...")
                await input_elem.press("Enter")

            # 4. Wait for network response or DOM element update
            max_wait_ms = int(self.timeout * 1000)
            interval_ms = 400
            elapsed = 0
            extracted_text = ""

            while elapsed < max_wait_ms:
                await asyncio.sleep(interval_ms / 1000)
                elapsed += interval_ms

                # Priority 1: If network response was intercepted directly
                if intercepted_responses:
                    extracted_text = intercepted_responses[-1]
                    logger.info(f"Captured clean response directly via Network Interception ({len(extracted_text)} chars)")
                    break

                # Priority 2: Check for new response elements in DOM
                loading_placeholders = {"typing...", "typing", "thinking...", "thinking", "loading...", "loading", "generating..."}
                current_responses = await page.query_selector_all(self.response_selector)
                if len(current_responses) > prev_count:
                    latest_elem = current_responses[-1]
                    candidate_text = (await latest_elem.inner_text()).strip()
                    if candidate_text and candidate_text.lower() not in loading_placeholders:
                        extracted_text = candidate_text
                        break
                elif len(current_responses) == prev_count and prev_count > 0:
                    latest_elem = current_responses[-1]
                    current_text = (await latest_elem.inner_text()).strip()
                    if current_text and current_text != (await prev_responses[-1].inner_text()).strip() and current_text.lower() not in loading_placeholders:
                        extracted_text = current_text
                        break

            # Priority 3: If no specific selector matched, use Snapshot Delta Diffing
            if not extracted_text or extracted_text.lower() in {"typing...", "typing", "thinking...", "loading..."}:
                after_body = await page.query_selector("body")
                after_text = (await after_body.inner_text()).strip() if after_body else ""
                diffed = compute_delta_text(before_text, after_text, sent_prompt=prompt)
                if diffed and diffed.lower() not in {"typing...", "typing", "thinking...", "loading..."}:
                    extracted_text = diffed

            # 5. Clean and isolate assistant dialogue
            isolated_reply = isolate_assistant_response(extracted_text, sent_prompt=prompt)
            logger.info(f"Extracted isolated response ({len(isolated_reply)} chars): {isolated_reply[:90]!r}...")
            return isolated_reply
        except Exception as err:
            logger.error(f"Playwright interaction error on {self.url}: {err}")
            raise
        finally:
            page.remove_listener("response", _on_response)
            await page.close()
