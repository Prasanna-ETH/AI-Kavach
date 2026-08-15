"""REST API Adapter supporting JSON templating, custom headers, and dotted-path JSON parsing."""

import json
import re
from typing import Any, Dict, Optional, Union
import httpx
import yaml

from scanner.adapters.base import BaseAdapter


def extract_dotted_path(data: Any, path: str) -> str:
    """Extract a value from nested dicts/lists using dotted-path notation.

    Examples:
        'message.content' -> data['message']['content']
        'choices.0.message.content' -> data['choices'][0]['message']['content']

    Args:
        data: Parsed JSON data structure (dict or list).
        path: Dotted-path string.

    Returns:
        String value at specified key path.

    Raises:
        ValueError: If key or index does not exist or result is not convertible to string.
    """
    if not path:
        if isinstance(data, str):
            return data
        return json.dumps(data)

    current = data
    parts = path.split(".")
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                raise ValueError(f"Key '{part}' not found in response dictionary.")
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
                current = current[idx]
            except (ValueError, IndexError) as err:
                raise ValueError(f"Invalid list index '{part}' in response data.") from err
        else:
            raise ValueError(f"Cannot traverse into non-container type '{type(current).__name__}' with key '{part}'.")

    if isinstance(current, (dict, list)):
        return json.dumps(current)
    return str(current)


def normalize_body_template(template_input: Union[str, Dict[str, Any]]) -> Any:
    """Parse and normalize a JSON template, repairing Windows/PowerShell quote stripping if needed."""
    if isinstance(template_input, (dict, list)):
        return template_input

    if not isinstance(template_input, str):
        return {"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}

    s = template_input.strip()

    # 1. Direct JSON parse attempt
    try:
        return json.loads(s)
    except Exception:
        pass

    # 2. Repair PowerShell-stripped quotes
    repaired = s.replace("{{PROMPT}}", '"{{PROMPT}}"').replace('""{{PROMPT}}""', '"{{PROMPT}}"')
    # Add double quotes to unquoted dictionary keys: {model: -> {"model":
    repaired = re.sub(r'([{,]\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\2":', repaired)
    # Add double quotes to unquoted string values
    repaired = re.sub(r':\s*([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+)(?=[,}])', r':"\1"', repaired)
    repaired = re.sub(r':\s*([a-zA-Z0-9_.-]+)(?=[,}])', r':"\1"', repaired)

    try:
        return json.loads(repaired)
    except Exception:
        pass

    # 3. Fallback: YAML parse with safe string substitution
    try:
        temp = s.replace("{{PROMPT}}", "__PROMPT_PLACEHOLDER__")
        loaded = yaml.safe_load(temp)
        if isinstance(loaded, (dict, list)):
            def restore(obj: Any) -> Any:
                if isinstance(obj, str):
                    return obj.replace("__PROMPT_PLACEHOLDER__", "{{PROMPT}}")
                elif isinstance(obj, dict):
                    return {k: restore(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [restore(item) for item in obj]
                return obj
            return restore(loaded)
    except Exception:
        pass

    # 4. Default OpenAI/Ollama format fallback
    return {
        "model": "qwen2.5:3b",
        "messages": [{"role": "user", "content": "{{PROMPT}}"}],
    }


def inject_prompt_into_payload(template_obj: Any, prompt: str) -> Any:
    """Recursively replace '{{PROMPT}}' in a JSON structure with prompt text.

    Args:
        template_obj: Parsed dictionary, list, or primitive.
        prompt: Attack prompt string.

    Returns:
        Structure with '{{PROMPT}}' replaced by prompt string.
    """
    if isinstance(template_obj, str):
        return template_obj.replace("{{PROMPT}}", prompt)
    elif isinstance(template_obj, dict):
        return {k: inject_prompt_into_payload(v, prompt) for k, v in template_obj.items()}
    elif isinstance(template_obj, list):
        return [inject_prompt_into_payload(item, prompt) for item in template_obj]
    return template_obj


class RESTAdapter(BaseAdapter):
    """HTTP/REST Endpoint Adapter using httpx for payload transmission."""

    def __init__(
        self,
        url: str,
        body_template: Union[str, Dict[str, Any]],
        response_field: str = "message.content",
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize RESTAdapter.

        Args:
            url: Target REST API endpoint URL.
            body_template: JSON template string or dict containing '{{PROMPT}}'.
            response_field: Dotted path to extract model output text.
            headers: Optional HTTP headers dictionary.
            timeout: HTTP request timeout in seconds.
        """
        self.url = url
        self.response_field = response_field
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.parsed_template = normalize_body_template(body_template)

    async def send(self, prompt: str) -> str:
        """Send prompt to target endpoint asynchronously using httpx AsyncClient.

        Args:
            prompt: Payload text to send.

        Returns:
            Extracted response text string.
        """
        json_body = inject_prompt_into_payload(self.parsed_template, prompt)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.url,
                json=json_body,
                headers=self.headers,
            )

            # Raise HTTP errors (e.g. 429, 500, 503) for engine backoff handling
            response.raise_for_status()

            try:
                data = response.json()
                return extract_dotted_path(data, self.response_field)
            except json.JSONDecodeError:
                # If target returns plain text instead of JSON
                return response.text
