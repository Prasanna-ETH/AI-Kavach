"""Shared HTTP client utility for calling local Ollama models."""

import logging
from typing import Optional
import httpx

logger = logging.getLogger("scanner.common.ollama")


async def call_local_ollama(
    prompt: str,
    model: str = "qwen2.5:0.5b",
    ollama_url: str = "http://localhost:11434/api/chat",
    timeout: float = 30.0,
    system_prompt: Optional[str] = None,
) -> str:
    """Send a prompt to the Ollama chat endpoint and return raw text content from the model response.

    Args:
        prompt: User prompt text to send.
        model: Model name to use.
        ollama_url: Ollama chat endpoint URL.
        timeout: Request timeout in seconds.
        system_prompt: Optional system message.

    Returns:
        Raw text content string from the model's response.
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
        return data.get("message", {}).get("content", "")
