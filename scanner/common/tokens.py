"""Token calculation and estimation utilities for LLM Sentinel."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple


def estimate_tokens(text: Optional[str]) -> int:
    """Estimate token count for a text string using standard subword heuristics (~3.8 chars/token).

    Args:
        text: Text string to estimate.

    Returns:
        Estimated number of tokens (0 if empty).
    """
    if not text:
        return 0
    clean_text = text.strip()
    if not clean_text:
        return 0

    # Rule of thumb for English / technical / code text:
    # 1 token ≈ 3.8 characters (or max of char-length/3.8 and word_count * 1.3)
    char_estimate = len(clean_text) / 3.8
    words = re.findall(r"\w+|[^\w\s]", clean_text)
    word_estimate = len(words) * 1.25

    return max(1, int(round((char_estimate + word_estimate) / 2)))


def extract_or_estimate_tokens(
    response_json: Any,
    prompt_text: str,
    response_text: str,
) -> Tuple[int, int]:
    """Extract exact prompt/completion token usage from standard LLM response payload, or estimate.

    Supports:
    - Ollama: prompt_eval_count (prompt), eval_count (completion)
    - OpenAI / vLLM / LiteLLM: usage.prompt_tokens, usage.completion_tokens
    - Anthropic: usage.input_tokens, usage.output_tokens
    - Gemini: usageMetadata.promptTokenCount, usageMetadata.candidatesTokenCount

    Args:
        response_json: Parsed response dictionary from target API, if available.
        prompt_text: Attack prompt text sent to target.
        response_text: Extracted response text from target.

    Returns:
        Tuple of (prompt_tokens, completion_tokens).
    """
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None

    if isinstance(response_json, dict):
        # 1. Ollama format
        if "prompt_eval_count" in response_json:
            try:
                prompt_tokens = int(response_json["prompt_eval_count"])
            except (ValueError, TypeError):
                pass
        if "eval_count" in response_json:
            try:
                completion_tokens = int(response_json["eval_count"])
            except (ValueError, TypeError):
                pass

        # 2. OpenAI / vLLM / LiteLLM format
        usage = response_json.get("usage")
        if isinstance(usage, dict):
            if "prompt_tokens" in usage:
                try:
                    prompt_tokens = int(usage["prompt_tokens"])
                except (ValueError, TypeError):
                    pass
            if "completion_tokens" in usage:
                try:
                    completion_tokens = int(usage["completion_tokens"])
                except (ValueError, TypeError):
                    pass
            # Anthropic Messages API
            if "input_tokens" in usage:
                try:
                    prompt_tokens = int(usage["input_tokens"])
                except (ValueError, TypeError):
                    pass
            if "output_tokens" in usage:
                try:
                    completion_tokens = int(usage["output_tokens"])
                except (ValueError, TypeError):
                    pass

        # 3. Gemini format
        usage_meta = response_json.get("usageMetadata")
        if isinstance(usage_meta, dict):
            if "promptTokenCount" in usage_meta:
                try:
                    prompt_tokens = int(usage_meta["promptTokenCount"])
                except (ValueError, TypeError):
                    pass
            if "candidatesTokenCount" in usage_meta:
                try:
                    completion_tokens = int(usage_meta["candidatesTokenCount"])
                except (ValueError, TypeError):
                    pass

    # Fallback to estimation if not present
    if prompt_tokens is None:
        prompt_tokens = estimate_tokens(prompt_text)
    if completion_tokens is None:
        completion_tokens = estimate_tokens(response_text)

    return (max(0, prompt_tokens), max(0, completion_tokens))
