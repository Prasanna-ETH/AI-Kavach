"""Shared HTTP client utility for calling local Ollama models with token usage tracking."""

from __future__ import annotations

import logging
from typing import Optional, Tuple
import httpx

from scanner.common.tokens import estimate_tokens

logger = logging.getLogger("scanner.common.ollama")


async def call_local_ollama(
    prompt: str,
    model: str = "qwen2.5:0.5b",
    ollama_url: str = "http://localhost:11434/api/chat",
    timeout: float = 30.0,
    system_prompt: Optional[str] = None,
) -> str:
    """Send a prompt to the Ollama chat endpoint and return raw text content from the model response."""
    content, _, _ = await call_local_ollama_with_usage(
        prompt=prompt,
        model=model,
        ollama_url=ollama_url,
        timeout=timeout,
        system_prompt=system_prompt,
    )
    return content


async def call_local_ollama_with_usage(
    prompt: str,
    model: str = "qwen2.5:0.5b",
    ollama_url: str = "http://localhost:11434/api/chat",
    timeout: float = 30.0,
    system_prompt: Optional[str] = None,
) -> Tuple[str, int, int]:
    """Send a prompt to the Ollama chat endpoint and return (content, prompt_tokens, completion_tokens).

    Args:
        prompt: User prompt text to send.
        model: Model name to use.
        ollama_url: Ollama chat endpoint URL.
        timeout: Request timeout in seconds.
        system_prompt: Optional system message.

    Returns:
        Tuple of (content, prompt_tokens, completion_tokens).
    """
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    request_body = {
        "model": model,
        "messages": messages,
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        res = await client.post(ollama_url, json=request_body)
        res.raise_for_status()
        data = res.json()
        content = data.get("message", {}).get("content", "")

        # Extract real tokens reported by Ollama engine, or estimate
        prompt_tokens = data.get("prompt_eval_count")
        if prompt_tokens is None:
            full_prompt = (system_prompt or "") + "\n" + prompt
            prompt_tokens = estimate_tokens(full_prompt)

        completion_tokens = data.get("eval_count")
        if completion_tokens is None:
            completion_tokens = estimate_tokens(content)

        return content, int(prompt_tokens), int(completion_tokens)
