"""Scan execution engine with asyncio concurrency, inter-request delay, exponential backoff, circuit breaker, and multi-turn attack orchestration."""

import asyncio
from datetime import datetime, timezone
import logging
import random
import time
from typing import Callable, List, Optional
import httpx

from scanner.adapters.base import BaseAdapter
from scanner.attacker.attacker_llm import AttackerLLM
from scanner.converters.base import Converter
from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.likert_judge import LikertJudge
from scanner.judge.llm_judge import LLMJudge
from scanner.judge.multiturn_judge import judge_conversation
from scanner.models import ConversationTurn, Finding, MultiTurnFinding, MultiTurnPayload, Payload, ScanResult
from scanner.scoring import calculate_likert_distribution, calculate_posture_score

logger = logging.getLogger("scanner.engine")


class ScanEngine:
    """Orchestrates asynchronous payload transmission, retry backoff, circuit breaking, and multi-turn attacks."""

    def __init__(
        self,
        adapter: BaseAdapter,
        delay: float = 0.0,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 10,
        concurrency: int = 5,
        use_llm_judge: bool = False,
        ollama_url: str = "http://localhost:11434/api/chat",
        judge_model: str = "qwen2.5:3b",
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
            judge_model: Ollama model name for LLM Judge.
        """
        self.adapter = adapter
        self.delay = delay
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.concurrency = max(1, concurrency)
        self.use_llm_judge = use_llm_judge
        self.ollama_url = ollama_url
        self.judge_model = judge_model
        self.heuristic_judge = HeuristicJudge()
        self.llm_judge = LLMJudge(ollama_url=ollama_url, model=judge_model)
        self.likert_judge = LikertJudge(ollama_url=ollama_url, model=judge_model)

    async def _execute_with_backoff(self, prompt: str, payload_id: str) -> tuple[str, Optional[str]]:
        """Execute a payload send request asynchronously with exponential backoff on HTTP 429/503.

        Returns:
            Tuple of (response_text, error_message).
        """
        retries = 0
        base_backoff = 1.0

        while True:
            try:
                logger.info(f"Sending prompt for [{payload_id}] to target: {prompt[:80]!r}...")
                response_text = await self.adapter.send(prompt)
                logger.info(f"Target response for [{payload_id}] ({len(response_text)} chars): {response_text[:90]!r}...")
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
                        f"Payload {payload_id} received HTTP {status_code}. Retrying in {wait_time:.2f}s (Attempt {retries}/{self.max_retries})"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                error_msg = f"HTTP {status_code}: {err.response.text or str(err)}"
                logger.error(f"Payload {payload_id} failed with {error_msg}")
                return "", error_msg
            except Exception as err:
                error_msg = f"Request error: {str(err)}"
                logger.error(f"Payload {payload_id} failed with {error_msg}")
                return "", error_msg

    async def _send_and_judge(
        self,
        payload: Payload,
        prompt_to_send: str,
        converter_name: Optional[str] = None,
    ) -> Finding:
        """Send prompt to target and evaluate with Likert/Heuristic judge.

        Args:
            payload: Payload definition object.
            prompt_to_send: Actual text sent to target (could be converted or plain).
            converter_name: Name of converter used, or None if plain text baseline.

        Returns:
            Finding object with evaluation result.
        """
        response_text, error = await self._execute_with_backoff(prompt_to_send, payload.id)

        if error:
            finding = Finding(
                payload=payload,
                response_text="",
                vulnerable=False,
                severity=payload.severity,
                confidence=0.0,
                judge_type="none",
                reasoning=f"Transmission failed: {error}",
                error=error,
                converter_used=converter_name,
                original_prompt=payload.prompt if converter_name else None,
                likert_score=0,
                sent_prompt=prompt_to_send,
                target_prompt_tokens=0,
                target_completion_tokens=0,
                judge_prompt_tokens=0,
                judge_completion_tokens=0,
                total_tokens=0,
            )
        else:
            temp_payload = Payload(
                id=payload.id,
                category=payload.category,
                owasp_id=payload.owasp_id,
                prompt=prompt_to_send,
                severity=payload.severity,
                heuristic_keywords=payload.heuristic_keywords,
                requires_llm_judge=payload.requires_llm_judge,
                expected_vulnerable=payload.expected_vulnerable,
                source=payload.source,
            )

            if payload.requires_llm_judge or self.use_llm_judge:
                finding = await self.likert_judge.evaluate(temp_payload, response_text)
            else:
                finding = await self.heuristic_judge.evaluate(temp_payload, response_text)
                if finding.likert_score is None or finding.likert_score == 0 and finding.vulnerable:
                    finding.likert_score = 4 if finding.vulnerable else 0

            finding.payload = payload
            finding.converter_used = converter_name
            finding.original_prompt = payload.prompt if converter_name else None
            finding.sent_prompt = prompt_to_send

            # Extract or estimate target endpoint tokens
            from scanner.common.tokens import estimate_tokens, extract_or_estimate_tokens
            last_usage = getattr(self.adapter, "last_usage", None)
            if last_usage:
                finding.target_prompt_tokens, finding.target_completion_tokens = last_usage
            else:
                finding.target_prompt_tokens = estimate_tokens(prompt_to_send)
                finding.target_completion_tokens = estimate_tokens(response_text)

            finding.total_tokens = (
                finding.target_prompt_tokens
                + finding.target_completion_tokens
                + (finding.judge_prompt_tokens or 0)
                + (finding.judge_completion_tokens or 0)
            )

        variant_label = converter_name if converter_name else "plain"
        logger.info(
            f"Variant [{variant_label}] evaluated for payload {payload.id} ({payload.category}) -> "
            f"judge={finding.judge_type}, likert={finding.likert_score}/4, vulnerable={finding.vulnerable}, "
            f"tokens(tgt={finding.target_prompt_tokens}+{finding.target_completion_tokens}, "
            f"jdg={finding.judge_prompt_tokens}+{finding.judge_completion_tokens}, tot={finding.total_tokens}), "
            f"reasoning={finding.reasoning[:100]!r}"
        )
        return finding

    async def run(
        self,
        payloads: List[Payload],
        progress_callback: Optional[Callable[[int, int, Payload, Optional[Finding]], None]] = None,
    ) -> ScanResult:
        """Run full single-turn security scan against all payloads concurrently.

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

        logger.info(f"Starting single-turn scan: total_payloads={total}, concurrency={self.concurrency}, delay={self.delay}s")

        async def worker(index: int, payload: Payload) -> Optional[Finding]:
            nonlocal consecutive_failures, circuit_broken

            async with semaphore:
                async with state_lock:
                    if circuit_broken:
                        logger.warning(f"Skipping payload {payload.id} due to broken circuit breaker.")
                        return None

                if progress_callback:
                    progress_callback(index, total, payload, None)

                finding = await self._send_and_judge(payload, payload.prompt, converter_name=None)

                async with state_lock:
                    if finding.error:
                        consecutive_failures += 1
                        if consecutive_failures >= self.circuit_breaker_threshold:
                            circuit_broken = True
                            logger.error(f"Circuit breaker triggered after {consecutive_failures} consecutive failures!")
                    else:
                        consecutive_failures = 0

                    findings.append(finding)

                if progress_callback:
                    progress_callback(index, total, payload, finding)

                if self.delay > 0:
                    await asyncio.sleep(self.delay)

                return finding

        tasks = [asyncio.create_task(worker(idx, p)) for idx, p in enumerate(payloads, start=1)]
        await asyncio.gather(*tasks, return_exceptions=True)

        payload_order_map = {p.id: i for i, p in enumerate(payloads)}
        findings.sort(key=lambda f: payload_order_map.get(f.payload.id, 99999))

        end_dt = datetime.now(timezone.utc)
        end_time_iso = end_dt.isoformat()
        duration = (end_dt - start_dt).total_seconds()
        target_url = getattr(self.adapter, "url", "unknown_target")

        dist = calculate_likert_distribution(findings)
        posture_score, grade, category_scores = calculate_posture_score(findings)

        total_target_tokens = sum((f.target_prompt_tokens + f.target_completion_tokens) for f in findings)
        total_judge_tokens = sum((f.judge_prompt_tokens + f.judge_completion_tokens) for f in findings)
        total_tokens = sum(f.total_tokens for f in findings)

        # Estimate judge tokens saved whenever fast heuristic/signature filters short-circuited
        from scanner.common.tokens import estimate_tokens
        judge_tokens_saved = sum(
            (estimate_tokens(f.sent_prompt or f.payload.prompt) + estimate_tokens(f.response_text) + 250)
            for f in findings
            if f.judge_type in ("fast_prefilter", "signature_engine", "refusal_engine", "heuristic")
        )

        return ScanResult(
            target_url=target_url,
            start_time=start_time_iso,
            end_time=end_time_iso,
            total_payloads=total,
            findings=findings,
            circuit_broken=circuit_broken,
            duration_seconds=duration,
            likert_distribution=dist,
            posture_score=posture_score,
            grade=grade,
            category_scores=category_scores,
            total_target_tokens=total_target_tokens,
            total_judge_tokens=total_judge_tokens,
            total_tokens=total_tokens,
            judge_tokens_saved=judge_tokens_saved,
        )

    async def run_multiturn_scan(
        self,
        attacker: AttackerLLM,
        payloads: List[MultiTurnPayload],
        progress_callback: Optional[Callable[[int, int, MultiTurnPayload, int, int, str, Optional[MultiTurnFinding]], None]] = None,
    ) -> List[MultiTurnFinding]:
        """Run multi-turn adversarial attack scan against target endpoint.

        Args:
            attacker: AttackerLLM instance.
            payloads: List of MultiTurnPayload items.
            progress_callback: Optional callback receiving (payload_index, total_payloads, payload, current_turn, max_turns, status_msg, finding).

        Returns:
            List of MultiTurnFinding results.
        """
        results: List[MultiTurnFinding] = []
        total_payloads = len(payloads)

        for p_idx, payload in enumerate(payloads, start=1):
            # Enforce hard safety cap of 8 turns max per conversation
            max_turns = min(payload.max_turns, 8)
            transcript: List[ConversationTurn] = []
            consecutive_failures = 0
            circuit_broken = False

            logger.info(
                f"Starting Multi-Turn Payload [{payload.id}] ({payload.category}) - Max Turns: {max_turns}"
            )

            # Turn 1: Opening prompt
            from scanner.common.tokens import estimate_tokens
            if progress_callback:
                progress_callback(p_idx, total_payloads, payload, 1, max_turns, "Sending opening prompt...", None)

            start_t = time.time()
            t1_prompt_tokens = estimate_tokens(payload.opening_prompt)
            transcript.append(
                ConversationTurn(
                    turn_number=1,
                    role="attacker",
                    content=payload.opening_prompt,
                    timestamp=start_t,
                    prompt_tokens=t1_prompt_tokens,
                )
            )
            logger.info(f"[{payload.id}] Turn 1/{max_turns} [Attacker]: {payload.opening_prompt[:80]}...")

            resp_text, error = await self._execute_with_backoff(payload.opening_prompt, payload.id)
            if error:
                finding = MultiTurnFinding(
                    payload_id=payload.id,
                    category=payload.category,
                    owasp_id=payload.owasp_id,
                    vulnerable=False,
                    severity=payload.severity,
                    confidence=0.0,
                    reasoning=f"Transmission failed on turn 1: {error}",
                    full_transcript=transcript,
                    error=error,
                    likert_score=0,
                    target_prompt_tokens=t1_prompt_tokens,
                    target_completion_tokens=0,
                    total_tokens=t1_prompt_tokens,
                )
                results.append(finding)
                if progress_callback:
                    progress_callback(p_idx, total_payloads, payload, 1, max_turns, f"ERROR: {error}", finding)
                continue

            t1_resp_tokens = estimate_tokens(resp_text)
            transcript.append(
                ConversationTurn(
                    turn_number=1,
                    role="target",
                    content=resp_text,
                    timestamp=time.time(),
                    completion_tokens=t1_resp_tokens,
                )
            )
            logger.info(f"[{payload.id}] Turn 1/{max_turns} [Target]: {resp_text[:80]}...")

            if self.delay > 0:
                await asyncio.sleep(self.delay)

            # Multi-turn escalation loop (Turn 2 up to max_turns)
            for turn_num in range(2, max_turns + 1):
                if progress_callback:
                    progress_callback(
                        p_idx,
                        total_payloads,
                        payload,
                        turn_num,
                        max_turns,
                        "Attacker generating next escalation turn...",
                        None,
                    )

                next_prompt, should_stop_early, reasoning = await attacker.generate_next_turn(
                    escalation_strategy=payload.escalation_strategy,
                    conversation_so_far=transcript,
                    stop_condition_hint=payload.stop_condition_hint,
                )

                if should_stop_early:
                    logger.info(
                        f"[{payload.id}] Attacker LLM requested early stop at turn {turn_num - 1}: {reasoning}"
                    )
                    break

                tn_prompt_tokens = estimate_tokens(next_prompt)
                transcript.append(
                    ConversationTurn(
                        turn_number=turn_num,
                        role="attacker",
                        content=next_prompt,
                        timestamp=time.time(),
                        prompt_tokens=tn_prompt_tokens,
                    )
                )
                logger.info(f"[{payload.id}] Turn {turn_num}/{max_turns} [Attacker]: {next_prompt[:80]}...")

                target_resp, err = await self._execute_with_backoff(next_prompt, payload.id)
                if err:
                    consecutive_failures += 1
                    logger.error(f"[{payload.id}] Turn {turn_num} target request failed: {err}")
                    if consecutive_failures >= self.circuit_breaker_threshold:
                        circuit_broken = True
                        break
                    continue

                consecutive_failures = 0
                tn_resp_tokens = estimate_tokens(target_resp)
                transcript.append(
                    ConversationTurn(
                        turn_number=turn_num,
                        role="target",
                        content=target_resp,
                        timestamp=time.time(),
                        completion_tokens=tn_resp_tokens,
                    )
                )
                logger.info(f"[{payload.id}] Turn {turn_num}/{max_turns} [Target]: {target_resp[:80]}...")

                if self.delay > 0:
                    await asyncio.sleep(self.delay)

            # Evaluate transcript with MultiTurnJudge
            if progress_callback:
                progress_callback(
                    p_idx,
                    total_payloads,
                    payload,
                    len(transcript) // 2,
                    max_turns,
                    "Evaluating full transcript with Multi-Turn Judge...",
                    None,
                )

            mt_finding = await judge_conversation(
                payload=payload,
                transcript=transcript,
                ollama_url=self.ollama_url,
                model=self.judge_model or attacker.model,
            )

            mt_finding.likert_score = 4 if mt_finding.vulnerable else 0

            # Calculate total multi-turn target tokens
            tot_tgt_prompt = sum(t.prompt_tokens for t in transcript if t.role == "attacker")
            tot_tgt_comp = sum(t.completion_tokens for t in transcript if t.role == "target")
            mt_finding.target_prompt_tokens = tot_tgt_prompt
            mt_finding.target_completion_tokens = tot_tgt_comp
            mt_finding.total_tokens = (
                tot_tgt_prompt
                + tot_tgt_comp
                + (mt_finding.judge_prompt_tokens or 0)
                + (mt_finding.judge_completion_tokens or 0)
            )

            results.append(mt_finding)

            if progress_callback:
                status_str = f"VULNERABLE (Turn {mt_finding.succeeded_at_turn})" if mt_finding.vulnerable else "PASSED"
                progress_callback(
                    p_idx,
                    total_payloads,
                    payload,
                    len(transcript) // 2,
                    max_turns,
                    f"Completed -> {status_str}",
                    mt_finding,
                )

        return results


async def run_scan_with_converters(
    adapter: BaseAdapter,
    payloads: List[Payload],
    converters: List[Converter],
    delay: float = 1.0,
    use_llm_judge: bool = False,
    ollama_url: str = "http://localhost:11434/api/chat",
    judge_model: str = "qwen2.5:3b",
    progress_callback: Optional[Callable[[int, int, Payload, Optional[str], Finding], None]] = None,
) -> List[Finding]:
    """Run security scan sending both plain-text baseline and converted variants for each payload.

    Args:
        adapter: BaseAdapter target endpoint adapter.
        payloads: List of Payload items to scan.
        converters: List of Converter instances to apply.
        delay: Delay in seconds between requests.
        use_llm_judge: Whether to enforce LLM judge.
        ollama_url: Ollama API URL endpoint.
        judge_model: Ollama model name for LLM judge.
        progress_callback: Optional callback receiving (payload_index, total_payloads, payload, variant_name, finding).

    Returns:
        List of Finding objects (plain text baseline findings and converter variant findings).
    """
    engine = ScanEngine(
        adapter=adapter,
        delay=delay,
        concurrency=1,
        use_llm_judge=use_llm_judge,
        ollama_url=ollama_url,
        judge_model=judge_model,
    )

    all_findings: List[Finding] = []
    total_payloads = len(payloads)

    for idx, payload in enumerate(payloads, start=1):
        # a. ALWAYS send and judge plain-text prompt first
        plain_finding = await engine._send_and_judge(payload, payload.prompt, converter_name=None)
        all_findings.append(plain_finding)

        if progress_callback:
            progress_callback(idx, total_payloads, payload, None, plain_finding)

        if delay > 0:
            await asyncio.sleep(delay)

        # b. For each converter in converters list: transform, send, judge, record
        for converter in converters:
            try:
                transformed_prompt = await converter.transform(payload.prompt)
            except Exception as err:
                logger.error(f"Converter '{converter.name}' transform failed on payload {payload.id}: {err}")
                transformed_prompt = payload.prompt

            conv_finding = await engine._send_and_judge(payload, transformed_prompt, converter_name=converter.name)
            all_findings.append(conv_finding)

            if progress_callback:
                progress_callback(idx, total_payloads, payload, converter.name, conv_finding)

            if delay > 0:
                await asyncio.sleep(delay)

    return all_findings
