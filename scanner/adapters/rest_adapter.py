"""REST API Adapter supporting JSON templating, custom headers, and dotted-path JSON parsing."""

import json
from typing import Any, Dict, Optional, Union
import httpx

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

        if isinstance(body_template, str):
            try:
                # Store parsed json structure if valid, else keep template string
                self.parsed_template = json.loads(body_template)
                self.raw_template = None
            except json.JSONDecodeError:
                self.parsed_template = None
                self.raw_template = body_template
        else:
            self.parsed_template = body_template
            self.raw_template = None

    def send(self, prompt: str) -> str:
        """Send prompt to target endpoint using httpx synchronous client.

        Args:
            prompt: Payload text to send.

        Returns:
            Extracted response text string.
        """
        if self.parsed_template is not None:
            json_body = inject_prompt_into_payload(self.parsed_template, prompt)
            content = None
        else:
            # String replacement fallback
            raw_str = self.raw_template.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
            json_body = None
            content = raw_str

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                self.url,
                json=json_body,
                content=content,
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
