"""Scan execution engine with inter-request delay, exponential backoff, and circuit breaker."""

from datetime import datetime, timezone
import random
import time
from typing import Callable, List, Optional
import httpx

from scanner.adapters.base import BaseAdapter
from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.llm_judge import LLMJudge
from scanner.models import Finding, Payload, ScanResult


class ScanEngine:
    """Orchestrates payload transmission, retry backoff, circuit breaking, and evaluation."""

    def __init__(
        self,
        adapter: BaseAdapter,
        delay: float = 0.5,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 3,
        use_llm_judge: bool = False,
        ollama_url: str = "http://localhost:11434/api/chat",
    ) -> None:
        """Initialize ScanEngine.

        Args:
            adapter: Endpoint adapter instance implementing BaseAdapter.
            delay: Delay in seconds between payload dispatches.
            max_retries: Maximum backoff retries on HTTP 429/503.
            circuit_breaker_threshold: Max consecutive failures before breaking circuit.
            use_llm_judge: Whether to enforce LLM judging for all payloads.
            ollama_url: Ollama API URL for LLM Judge.
        """
        self.adapter = adapter
        self.delay = delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.use_llm_judge = use_llm_judge
        self.heuristic_judge = HeuristicJudge()
        self.llm_judge = LLMJudge(ollama_url=ollama_url)

    def _execute_with_backoff(self, payload: Payload) -> tuple[str, Optional[str]]:
        """Execute a payload send request with exponential backoff on HTTP 429/503.

        Returns:
            Tuple of (response_text, error_message).
        """
        retries = 0
        base_backoff = 1.0

        while True:
            try:
                response_text = self.adapter.send(payload.prompt)
                return response_text, None
            except httpx.HTTPStatusError as err:
                status_code = err.response.status_code
                if status_code in (429, 503) and retries < self.max_retries:
                    retries += 1
                    # Check Retry-After header
                    retry_after = err.response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_time = float(retry_after)
                    else:
                        # Exponential backoff with jitter
                        jitter = random.uniform(0.1, 0.5)
                        wait_time = (base_backoff * (2 ** (retries - 1))) + jitter

                    time.sleep(wait_time)
                    continue
                return "", f"HTTP {status_code}: {err.response.text or str(err)}"
            except Exception as err:
                return "", f"Request error: {str(err)}"

    def run(
        self,
        payloads: List[Payload],
        progress_callback: Optional[Callable[[int, int, Payload, Optional[Finding]], None]] = None,
    ) -> ScanResult:
        """Run full security scan against all payloads.

        Args:
            payloads: List of Payload items to test.
            progress_callback: Optional callback receiving (index, total, payload, finding).

        Returns:
            ScanResult object.
        """
        start_dt = datetime.now(timezone.utc)
        start_time_iso = start_dt.isoformat()
        findings: List[Finding] = []
        consecutive_failures = 0
        circuit_broken = False
        total = len(payloads)

        for idx, payload in enumerate(payloads, start=1):
            if progress_callback:
                progress_callback(idx, total, payload, None)

            response_text, error = self._execute_with_backoff(payload)

            if error:
                consecutive_failures += 1
                finding = Finding(
                    payload=payload,
                    response_text="",
                    vulnerable=False,
                    severity=payload.severity,
                    confidence=0.0,
                    judge_type="none",
                    reasoning=f"Transmission failed: {error}",
                    error=error,
                )
            else:
                consecutive_failures = 0
                # Determine judge strategy
                if payload.requires_llm_judge or self.use_llm_judge:
                    finding = self.llm_judge.evaluate(payload, response_text)
                else:
                    finding = self.heuristic_judge.evaluate(payload, response_text)

            findings.append(finding)

            if progress_callback:
                progress_callback(idx, total, payload, finding)

            # Circuit breaker check
            if consecutive_failures >= self.circuit_breaker_threshold:
                circuit_broken = True
                break

            # Inter-request delay
            if self.delay > 0 and idx < total:
                time.sleep(self.delay)

        end_dt = datetime.now(timezone.utc)
        end_time_iso = end_dt.isoformat()
        duration = (end_dt - start_dt).total_seconds()

        target_url = getattr(self.adapter, "url", "unknown_target")

        return ScanResult(
            target_url=target_url,
            start_time=start_time_iso,
            end_time=end_time_iso,
            total_payloads=total,
            findings=findings,
            circuit_broken=circuit_broken,
            duration_seconds=duration,
        )
