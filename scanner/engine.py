"""Scan execution engine with asyncio concurrency, inter-request delay, exponential backoff, and circuit breaker."""

import asyncio
from datetime import datetime, timezone
import logging
import random
from typing import Callable, List, Optional
import httpx

from scanner.adapters.base import BaseAdapter
from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.llm_judge import LLMJudge
from scanner.models import Finding, Payload, ScanResult

logger = logging.getLogger("scanner.engine")


class ScanEngine:
    """Orchestrates asynchronous payload transmission, retry backoff, circuit breaking, and evaluation."""

    def __init__(
        self,
        adapter: BaseAdapter,
        delay: float = 0.0,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 3,
        concurrency: int = 5,
        use_llm_judge: bool = False,
        ollama_url: str = "http://localhost:11434/api/chat",
    ) -> None:
        """Initialize ScanEngine.

        Args:
            adapter: Endpoint adapter instance implementing BaseAdapter.
            delay: Delay in seconds between payload dispatches per worker.
            max_retries: Maximum backoff retries on HTTP 429/503.
            circuit_breaker_threshold: Max consecutive failures before breaking circuit.
            concurrency: Maximum number of simultaneous async requests.
            use_llm_judge: Whether to enforce LLM judging for all payloads.
            ollama_url: Ollama API URL for LLM Judge.
        """
        self.adapter = adapter
        self.delay = delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.concurrency = max(1, concurrency)
        self.use_llm_judge = use_llm_judge
        self.heuristic_judge = HeuristicJudge()
        self.llm_judge = LLMJudge(ollama_url=ollama_url)

    async def _execute_with_backoff(self, payload: Payload) -> tuple[str, Optional[str]]:
        """Execute a payload send request asynchronously with exponential backoff on HTTP 429/503.

        Returns:
            Tuple of (response_text, error_message).
        """
        retries = 0
        base_backoff = 1.0

        while True:
            try:
                logger.debug(f"Sending payload {payload.id} to target...")
                response_text = await self.adapter.send(payload.prompt)
                return response_text, None
            except httpx.HTTPStatusError as err:
                status_code = err.response.status_code
                if status_code in (429, 503) and retries < self.max_retries:
                    retries += 1
                    retry_after = err.response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_time = float(retry_after)
                    else:
                        jitter = random.uniform(0.1, 0.5)
                        wait_time = (base_backoff * (2 ** (retries - 1))) + jitter

                    logger.warning(
                        f"Payload {payload.id} received HTTP {status_code}. Retrying in {wait_time:.2f}s (Attempt {retries}/{self.max_retries})"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                error_msg = f"HTTP {status_code}: {err.response.text or str(err)}"
                logger.error(f"Payload {payload.id} failed with {error_msg}")
                return "", error_msg
            except Exception as err:
                error_msg = f"Request error: {str(err)}"
                logger.error(f"Payload {payload.id} failed with {error_msg}")
                return "", error_msg

    async def run(
        self,
        payloads: List[Payload],
        progress_callback: Optional[Callable[[int, int, Payload, Optional[Finding]], None]] = None,
    ) -> ScanResult:
        """Run full security scan against all payloads concurrently.

        Args:
            payloads: List of Payload items to test.
            progress_callback: Optional callback receiving (index, total, payload, finding).

        Returns:
            ScanResult object.
        """
        start_dt = datetime.now(timezone.utc)
        start_time_iso = start_dt.isoformat()
        total = len(payloads)

        semaphore = asyncio.Semaphore(self.concurrency)
        state_lock = asyncio.Lock()

        consecutive_failures = 0
        circuit_broken = False
        findings: List[Finding] = []
        completed_count = 0

        logger.info(f"Starting scan: total_payloads={total}, concurrency={self.concurrency}, delay={self.delay}s")

        async def worker(index: int, payload: Payload) -> Optional[Finding]:
            nonlocal consecutive_failures, circuit_broken, completed_count

            async with semaphore:
                # Check circuit breaker before sending
                async with state_lock:
                    if circuit_broken:
                        logger.warning(f"Skipping payload {payload.id} due to broken circuit breaker.")
                        return None

                if progress_callback:
                    progress_callback(index, total, payload, None)

                response_text, error = await self._execute_with_backoff(payload)

                if error:
                    async with state_lock:
                        consecutive_failures += 1
                        if consecutive_failures >= self.circuit_breaker_threshold:
                            circuit_broken = True
                            logger.error(
                                f"Circuit breaker triggered after {consecutive_failures} consecutive failures!"
                            )

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
                    async with state_lock:
                        consecutive_failures = 0

                    if payload.requires_llm_judge or self.use_llm_judge:
                        finding = await self.llm_judge.evaluate(payload, response_text)
                    else:
                        finding = await self.heuristic_judge.evaluate(payload, response_text)

                async with state_lock:
                    findings.append(finding)
                    completed_count += 1

                if progress_callback:
                    progress_callback(index, total, payload, finding)

                if finding.vulnerable:
                    logger.warning(
                        f"VULNERABILITY DETECTED [{finding.severity}] {payload.id} ({payload.category}): {finding.reasoning}"
                    )
                else:
                    logger.info(f"Payload passed [{payload.id}] ({payload.category})")

                if self.delay > 0:
                    await asyncio.sleep(self.delay)

                return finding

        tasks = [asyncio.create_task(worker(idx, p)) for idx, p in enumerate(payloads, start=1)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Sort findings by payload ID order to maintain deterministic result order
        payload_order_map = {p.id: i for i, p in enumerate(payloads)}
        findings.sort(key=lambda f: payload_order_map.get(f.payload.id, 99999))

        end_dt = datetime.now(timezone.utc)
        end_time_iso = end_dt.isoformat()
        duration = (end_dt - start_dt).total_seconds()

        target_url = getattr(self.adapter, "url", "unknown_target")

        logger.info(
            f"Scan completed in {duration:.2f}s: total={total}, vulnerable={sum(1 for f in findings if f.vulnerable)}, circuit_broken={circuit_broken}"
        )

        return ScanResult(
            target_url=target_url,
            start_time=start_time_iso,
            end_time=end_time_iso,
            total_payloads=total,
            findings=findings,
            circuit_broken=circuit_broken,
            duration_seconds=duration,
        )
