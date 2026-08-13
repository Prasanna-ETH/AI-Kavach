"""Unit tests for ScanEngine retry backoff and circuit breaker logic."""

from unittest.mock import MagicMock
import httpx
import pytest

from scanner.adapters.base import BaseAdapter
from scanner.engine import ScanEngine
from scanner.models import Payload


class MockAdapter(BaseAdapter):
    def __init__(self, responses: list):
        self.responses = responses
        self.call_count = 0
        self.url = "http://mock-target/api"

    def send(self, prompt: str) -> str:
        if self.call_count < len(self.responses):
            res = self.responses[self.call_count]
            self.call_count += 1
            if isinstance(res, Exception):
                raise res
            return res
        return "default ok"


def test_circuit_breaker_stops_scan() -> None:
    # 3 consecutive HTTP errors to trigger circuit breaker (threshold = 3)
    error = httpx.HTTPStatusError("Server error", request=MagicMock(), response=MagicMock(status_code=500, text="Internal Server Error"))
    adapter = MockAdapter([error, error, error, "should not be called"])

    engine = ScanEngine(adapter=adapter, delay=0.0, circuit_breaker_threshold=3)

    payloads = [
        Payload(id=f"P-00{i}", category="test", owasp_id="LLM01", prompt=f"Prompt {i}", severity="HIGH")
        for i in range(1, 6)
    ]

    result = engine.run(payloads)

    assert result.circuit_broken is True
    assert len(result.findings) == 3
    assert result.findings[0].error is not None


def test_retry_on_429_status_code() -> None:
    res_429 = httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=MagicMock(status_code=429, headers={"Retry-After": "0"}))
    adapter = MockAdapter([res_429, "Success response after retry"])

    engine = ScanEngine(adapter=adapter, delay=0.0, max_retries=2)
    payload = Payload(id="P-001", category="test", owasp_id="LLM01", prompt="Prompt 1", severity="HIGH", heuristic_keywords=["Success"])

    result = engine.run([payload])

    assert result.circuit_broken is False
    assert len(result.findings) == 1
    assert result.findings[0].vulnerable is True
    assert adapter.call_count == 2
