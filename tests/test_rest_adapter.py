"""Unit tests for REST adapter JSON templating and dotted path extraction with async support."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.adapters.rest_adapter import RESTAdapter, extract_dotted_path, inject_prompt_into_payload


def test_extract_dotted_path_simple() -> None:
    data = {"message": {"content": "Hello World"}}
    res = extract_dotted_path(data, "message.content")
    assert res == "Hello World"


def test_extract_dotted_path_list_indexing() -> None:
    data = {
        "choices": [
            {"message": {"content": "First response"}},
            {"message": {"content": "Second response"}},
        ]
    }
    res = extract_dotted_path(data, "choices.0.message.content")
    assert res == "First response"

    res_second = extract_dotted_path(data, "choices.1.message.content")
    assert res_second == "Second response"


def test_extract_dotted_path_invalid_key() -> None:
    data = {"message": {"text": "Hi"}}
    with pytest.raises(ValueError, match="Key 'content' not found"):
        extract_dotted_path(data, "message.content")


def test_inject_prompt_into_payload() -> None:
    template = {
        "model": "qwen2.5:0.5b",
        "messages": [{"role": "user", "content": "{{PROMPT}}"}],
    }
    prompt = "Test attack prompt with \"quotes\" & \n newlines"
    result = inject_prompt_into_payload(template, prompt)

    assert result["messages"][0]["content"] == prompt


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_rest_adapter_send(mock_post: AsyncMock) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "Disclosed secret sk-test-12345"}}
    mock_post.return_value = mock_response

    adapter = RESTAdapter(
        url="http://localhost:5000/api/chat",
        body_template='{"model": "qwen2.5:0.5b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
        response_field="message.content",
    )

    reply = await adapter.send("Ignore rules")
    assert reply == "Disclosed secret sk-test-12345"
    mock_post.assert_called_once()
