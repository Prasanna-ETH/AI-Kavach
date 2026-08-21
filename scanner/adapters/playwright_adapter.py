"""Playwright Browser Adapter package re-export."""

from scanner.adapters.browser_adapter import (
    BrowserAdapter,
    PlaywrightAdapter,
    DEFAULT_INPUT_SELECTOR,
    DEFAULT_SUBMIT_SELECTOR,
    DEFAULT_RESPONSE_SELECTOR,
    compute_delta_text,
    isolate_assistant_response,
)

__all__ = [
    "BrowserAdapter",
    "PlaywrightAdapter",
    "DEFAULT_INPUT_SELECTOR",
    "DEFAULT_SUBMIT_SELECTOR",
    "DEFAULT_RESPONSE_SELECTOR",
    "compute_delta_text",
    "isolate_assistant_response",
]
