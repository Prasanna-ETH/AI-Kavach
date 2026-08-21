"""Scan router — CRUD + SSE stream for live scan progress.

Endpoints
---------
POST /api/scans                        → start a new scan
GET  /api/scans                        → list all scans
GET  /api/scans/{scan_id}              → scan status + summary
GET  /api/scans/{scan_id}/stream       → SSE stream of live events
GET  /api/scans/{scan_id}/findings     → filterable findings list
GET  /api/scans/{scan_id}/report/html  → serve generated HTML report
GET  /api/scans/{scan_id}/report/json  → serve generated JSON report
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse

from backend.api.models import (
    BrowserTestSelectorsRequest,
    BrowserTestSelectorsResponse,
    FindingResponse,
    RetestPayloadRequest,
    ScanCreateResponse,
    ScanRequest,
    ScanSummary,
)
from backend.api.scan_store import (
    ScanState,
    create_scan as create_scan_record,
    get_scan,
    list_scans,
)

logger = logging.getLogger("sentinel.api.scans")

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Background scan task — calls into real engine, no logic duplicated
# ---------------------------------------------------------------------------

async def _run_scan_task(scan_id: str) -> None:
    """Orchestrate a scan run by calling into existing scanner modules."""
    from scanner.adapters.rest_adapter import RESTAdapter
    from scanner.attacker.attacker_llm import AttackerLLM
    from scanner.config import load_multiturn_payloads, load_payloads
    from scanner.converters.registry import get_converter
    from scanner.engine import ScanEngine, run_scan_with_converters
    from scanner.models import Finding, MultiTurnFinding, MultiTurnPayload, Payload
    from scanner.report.html_report import generate_html_report
    from scanner.report.json_report import generate_json_report, generate_multiturn_json_report
    from scanner.scoring import calculate_likert_distribution, calculate_posture_score

    state = get_scan(scan_id)
    if state is None:
        logger.error(f"Scan {scan_id} not found in store — aborting task")
        return

    cfg = state.config
    state.status = "running"
    state.start_time = datetime.now(timezone.utc).isoformat()
    try:
        state.output_dir.mkdir(parents=True, exist_ok=True)
        state.broadcast_sse("scan_started", {"scan_id": scan_id, "target_url": cfg.target_url})

        # Build adapter based on target_type (no logic duplicated)
        if getattr(cfg, "target_type", "rest") == "browser":
            from scanner.adapters.browser_adapter import (
                BrowserAdapter,
                DEFAULT_INPUT_SELECTOR,
                DEFAULT_SUBMIT_SELECTOR,
                DEFAULT_RESPONSE_SELECTOR,
            )
            adapter = BrowserAdapter(
                target_url=cfg.target_url,
                input_selector=cfg.input_selector or DEFAULT_INPUT_SELECTOR,
                send_button_selector=cfg.send_button_selector or DEFAULT_SUBMIT_SELECTOR,
                response_selector=cfg.response_selector or DEFAULT_RESPONSE_SELECTOR,
                wait_for_response_timeout=cfg.wait_for_response_timeout or 10.0,
                login_config=cfg.login_config,
            )
        else:
            body_template = cfg.body_template or (
                '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
            )
            headers: Dict[str, str] = {"Content-Type": "application/json"}
            if cfg.auth_header:
                if ":" in cfg.auth_header:
                    h_key, h_val = cfg.auth_header.split(":", 1)
                    headers[h_key.strip()] = h_val.strip()
                else:
                    headers["Authorization"] = cfg.auth_header.strip()

            adapter = RESTAdapter(
                url=cfg.target_url,
                body_template=body_template,
                response_field=cfg.response_field,
                headers=headers,
            )

        engine = ScanEngine(
            adapter=adapter,
            delay=cfg.delay,
            concurrency=1 if getattr(cfg, "target_type", "rest") == "browser" else cfg.concurrency,
            use_llm_judge=cfg.use_llm_judge,
            ollama_url=cfg.ollama_url,
            judge_model=cfg.judge_model,
        )

        # ---------------------------------------------------------------
        # SINGLE-TURN SCAN
        # ---------------------------------------------------------------
        if cfg.scan_mode == "single":
            payloads = load_payloads(pack_names=cfg.packs)
            if cfg.limit:
                payloads = payloads[: cfg.limit]
            state.total = len(payloads)
            state.broadcast_sse("total_set", {"total": state.total})

            def single_progress(
                index: int,
                total: int,
                payload: Payload,
                finding: Optional[Finding],
            ) -> None:
                state.progress = index
                if finding is None:
                    state.broadcast_sse(
                        "payload_started",
                        {"index": index, "total": total, "payload_id": payload.id,
                         "category": payload.category, "owasp_id": payload.owasp_id},
                    )
                    return
                fd = _finding_to_dict(finding)
                state.findings.append(fd)
                if finding.vulnerable:
                    state.vulnerable_count += 1
                state.broadcast_sse("finding", {"index": index, "total": total, "finding": fd})

            result = await engine.run(payloads, progress_callback=single_progress)
            _finalize_single(state, result)
            json_path = generate_json_report(result, state.output_dir / "report.json")
            generate_html_report(result, state.output_dir / "report.html")

        # ---------------------------------------------------------------
        # MULTI-TURN SCAN
        # ---------------------------------------------------------------
        elif cfg.scan_mode == "multiturn":
            mt_payloads = load_multiturn_payloads(pack_names=cfg.packs)
            if cfg.limit:
                mt_payloads = mt_payloads[: cfg.limit]
            # Apply max_turns cap from request (engine enforces hard cap of 8)
            for p in mt_payloads:
                p.max_turns = min(p.max_turns, cfg.max_turns, 8)
            state.total = len(mt_payloads)
            state.broadcast_sse("total_set", {"total": state.total})

            attacker = AttackerLLM(
                ollama_url=cfg.ollama_url,
                model=cfg.judge_model,
            )

            def mt_progress(
                p_idx: int,
                total: int,
                payload: MultiTurnPayload,
                current_turn: int,
                max_turns: int,
                status_msg: str,
                finding: Optional[MultiTurnFinding],
            ) -> None:
                state.progress = p_idx
                if finding is None:
                    state.broadcast_sse(
                        "turn_update",
                        {
                            "payload_id": payload.id,
                            "payload_index": p_idx,
                            "total": total,
                            "current_turn": current_turn,
                            "max_turns": max_turns,
                            "status_msg": status_msg,
                        },
                    )
                    return
                fd = _mt_finding_to_dict(finding)
                state.findings.append(fd)
                if finding.vulnerable:
                    state.vulnerable_count += 1
                state.broadcast_sse(
                    "finding",
                    {"index": p_idx, "total": total, "finding": fd},
                )

            mt_results = await engine.run_multiturn_scan(
                attacker=attacker,
                payloads=mt_payloads,
                progress_callback=mt_progress,
            )
            _finalize_multiturn(state, mt_results)
            generate_multiturn_json_report(mt_results, state.output_dir / "report.json")
            # HTML report for multi-turn (pass result=None, findings list handled inside)
            try:
                # generate_html_report may not support multiturn natively — write minimal stub
                _write_multiturn_html_stub(state, mt_results)
            except Exception as e:
                logger.warning(f"HTML report generation skipped: {e}")

        # ---------------------------------------------------------------
        # CONVERTER SCAN
        # ---------------------------------------------------------------
        elif cfg.scan_mode == "converter":
            payloads = load_payloads(pack_names=cfg.packs)
            if cfg.limit:
                payloads = payloads[: cfg.limit]

            converter_names = cfg.converters or []
            converter_instances = []
            for cname in converter_names:
                try:
                    converter_instances.append(get_converter(cname))
                except ValueError as err:
                    raise HTTPException(status_code=400, detail=str(err))

            # Each payload produces 1 + len(converters) findings
            state.total = len(payloads) * (1 + len(converter_instances))
            state.broadcast_sse("total_set", {"total": state.total})

            _conv_counter = [0]

            def conv_progress(
                idx: int,
                total_payloads: int,
                payload: Payload,
                variant_name: Optional[str],
                finding: Finding,
            ) -> None:
                _conv_counter[0] += 1
                state.progress = _conv_counter[0]
                fd = _finding_to_dict(finding)
                state.findings.append(fd)
                if finding.vulnerable:
                    state.vulnerable_count += 1
                state.broadcast_sse(
                    "finding",
                    {
                        "index": _conv_counter[0],
                        "total": state.total,
                        "finding": fd,
                        "variant": variant_name or "plain",
                    },
                )

            from datetime import datetime as dt
            start_t = dt.now(timezone.utc)
            conv_findings = await run_scan_with_converters(
                adapter=adapter,
                payloads=payloads,
                converters=converter_instances,
                delay=cfg.delay,
                use_llm_judge=cfg.use_llm_judge,
                ollama_url=cfg.ollama_url,
                judge_model=cfg.judge_model,
                progress_callback=conv_progress,
            )
            end_t = dt.now(timezone.utc)

            from scanner.models import ScanResult
            from scanner.scoring import calculate_likert_distribution, calculate_posture_score
            dist = calculate_likert_distribution(conv_findings)
            posture_score, grade, cat_scores = calculate_posture_score(conv_findings)
            result = ScanResult(
                target_url=cfg.target_url,
                start_time=start_t.isoformat(),
                end_time=end_t.isoformat(),
                total_payloads=len(conv_findings),
                findings=conv_findings,
                duration_seconds=(end_t - start_t).total_seconds(),
                likert_distribution=dist,
                posture_score=posture_score,
                grade=grade,
                category_scores=cat_scores,
            )
            _finalize_single(state, result)
            generate_json_report(result, state.output_dir / "report.json")
            generate_html_report(result, state.output_dir / "report.html")

        else:
            raise ValueError(f"Unknown scan_mode: {cfg.scan_mode}")

        state.status = "done"
        state.end_time = datetime.now(timezone.utc).isoformat()
        state.broadcast_sse("scan_complete", state.to_summary_dict())

    except Exception as exc:
        logger.exception(f"Scan {scan_id} failed: {exc}")
        state.status = "error"
        state.error_message = str(exc)
        state.end_time = datetime.now(timezone.utc).isoformat()
        state.broadcast_sse("scan_error", {"scan_id": scan_id, "error": str(exc)})
    finally:
        # Signal all SSE queues that the stream is done
        for q in list(state.sse_queues):
            try:
                q.put_nowait(None)  # sentinel
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Helper serialisers
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Any) -> Dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    return {
        "payload_id": f.payload.id,
        "category": f.payload.category,
        "owasp_id": f.payload.owasp_id,
        "prompt": f.payload.prompt,
        "sent_prompt": getattr(f, "sent_prompt", None),
        "response_text": f.response_text,
        "vulnerable": f.vulnerable,
        "severity": f.severity,
        "confidence": f.confidence,
        "judge_type": f.judge_type,
        "reasoning": f.reasoning,
        "error": f.error,
        "converter_used": f.converter_used,
        "original_prompt": f.original_prompt,
        "likert_score": getattr(f, "likert_score", 0),
        "target_prompt_tokens": getattr(f, "target_prompt_tokens", 0),
        "target_completion_tokens": getattr(f, "target_completion_tokens", 0),
        "judge_prompt_tokens": getattr(f, "judge_prompt_tokens", 0),
        "judge_completion_tokens": getattr(f, "judge_completion_tokens", 0),
        "total_tokens": getattr(f, "total_tokens", 0),
        "succeeded_at_turn": None,
        "full_transcript": None,
    }


def _mt_finding_to_dict(f: Any) -> Dict[str, Any]:
    """Convert a MultiTurnFinding to a JSON-serializable dict."""
    return {
        "payload_id": f.payload_id,
        "category": f.category,
        "owasp_id": f.owasp_id,
        "prompt": "",  # multi-turn has no single prompt
        "sent_prompt": None,
        "response_text": "",
        "vulnerable": f.vulnerable,
        "severity": f.severity,
        "confidence": f.confidence,
        "judge_type": "multiturn_judge",
        "reasoning": f.reasoning,
        "error": f.error,
        "converter_used": None,
        "original_prompt": None,
        "likert_score": getattr(f, "likert_score", 0),
        "target_prompt_tokens": getattr(f, "target_prompt_tokens", 0),
        "target_completion_tokens": getattr(f, "target_completion_tokens", 0),
        "judge_prompt_tokens": getattr(f, "judge_prompt_tokens", 0),
        "judge_completion_tokens": getattr(f, "judge_completion_tokens", 0),
        "total_tokens": getattr(f, "total_tokens", 0),
        "succeeded_at_turn": f.succeeded_at_turn,
        "full_transcript": [t.to_dict() for t in f.full_transcript],
        "attack_strategy": f.attack_strategy,
        "breached_vulnerabilities": f.breached_vulnerabilities,
        "breach_factors": f.breach_factors,
    }


def _finalize_single(state: ScanState, result: Any) -> None:
    from scanner.models import ScanResult as SR
    state.result_dict = result.to_dict()
    state.posture_score = result.posture_score
    state.grade = result.grade
    state.severity_counts = result.severity_counts
    state.likert_distribution = {str(k): v for k, v in result.likert_distribution.items()}
    state.category_scores = result.category_scores
    state.duration_seconds = result.duration_seconds
    state.circuit_broken = result.circuit_broken
    state.total_target_tokens = getattr(result, "total_target_tokens", 0)
    state.total_judge_tokens = getattr(result, "total_judge_tokens", 0)
    state.total_tokens = getattr(result, "total_tokens", 0)
    state.judge_tokens_saved = getattr(result, "judge_tokens_saved", 0)


def _finalize_multiturn(state: ScanState, results: List[Any]) -> None:
    total_target = sum(getattr(r, "target_prompt_tokens", 0) + getattr(r, "target_completion_tokens", 0) for r in results)
    total_judge = sum(getattr(r, "judge_prompt_tokens", 0) + getattr(r, "judge_completion_tokens", 0) for r in results)
    total_tok = sum(getattr(r, "total_tokens", 0) for r in results)

    state.total_target_tokens = total_target
    state.total_judge_tokens = total_judge
    state.total_tokens = total_tok
    state.judge_tokens_saved = 0

    state.result_dict = {
        "scan_type": "multi_turn_adversarial",
        "total_payloads": len(results),
        "vulnerable_count": state.vulnerable_count,
        "total_target_tokens": total_target,
        "total_judge_tokens": total_judge,
        "total_tokens": total_tok,
        "findings": state.findings,
    }


def _write_multiturn_html_stub(state: ScanState, results: List[Any]) -> None:
    """Write a minimal HTML stub for multi-turn scans since generate_html_report
    is designed for single-turn ScanResult objects."""
    vuln_count = sum(1 for r in results if r.vulnerable)
    rows = ""
    for r in results:
        badge = "🔴 VULNERABLE" if r.vulnerable else "✅ PASSED"
        rows += f"<tr><td>{r.payload_id}</td><td>{r.category}</td><td>{badge}</td><td>{r.severity}</td><td>{r.reasoning[:120]}</td></tr>"

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Multi-Turn Scan Report</title>
<style>body{{font-family:sans-serif;background:#0B1F3A;color:#E2E8F0;padding:2rem}}
table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #2D3A4A;padding:.5rem;text-align:left}}
th{{background:#14B8A6;color:#000}}tr:nth-child(even){{background:#112240}}</style></head>
<body><h1>Multi-Turn Adversarial Scan</h1>
<p>Total: {len(results)} | Vulnerable: {vuln_count}</p>
<table><tr><th>ID</th><th>Category</th><th>Result</th><th>Severity</th><th>Reasoning</th></tr>
{rows}</table></body></html>"""
    (state.output_dir / "report.html").write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# API route handlers
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanCreateResponse, status_code=202)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan (single-turn, multi-turn, or converter-based)."""
    state = create_scan_record(request)
    background_tasks.add_task(_run_scan_task, state.scan_id)
    return ScanCreateResponse(
        scan_id=state.scan_id,
        status="pending",
        message=f"Scan {state.scan_id} queued. Connect to /api/scans/{state.scan_id}/stream for live updates.",
    )


@router.post("/test-selectors", response_model=BrowserTestSelectorsResponse)
async def test_selectors(request: BrowserTestSelectorsRequest):
    """Validate browser chat/form selectors against target webpage before starting a scan."""
    from scanner.adapters.browser_adapter import (
        BrowserAdapter,
        DEFAULT_INPUT_SELECTOR,
        DEFAULT_SUBMIT_SELECTOR,
        DEFAULT_RESPONSE_SELECTOR,
    )

    adapter = BrowserAdapter(
        target_url=request.target_url,
        input_selector=request.input_selector or DEFAULT_INPUT_SELECTOR,
        send_button_selector=request.send_button_selector or DEFAULT_SUBMIT_SELECTOR,
        response_selector=request.response_selector or DEFAULT_RESPONSE_SELECTOR,
        wait_for_response_timeout=request.wait_for_response_timeout or 10.0,
        login_config=request.login_config,
    )

    try:
        report = await adapter.validate_selectors()
        return BrowserTestSelectorsResponse(**report)
    finally:
        await adapter.close()


@router.get("", response_model=List[ScanSummary])
async def list_all_scans():
    """List all scans, most-recent first."""
    return [ScanSummary(**s.to_summary_dict()) for s in list_scans()]


@router.get("/{scan_id}", response_model=ScanSummary)
async def get_scan_status(scan_id: str):
    """Get status and summary for a specific scan."""
    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return ScanSummary(**state.to_summary_dict())


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """Server-Sent Events stream delivering live per-payload progress."""
    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    state.sse_queues.append(queue)

    # If scan already done, send final state immediately then close
    if state.status in ("done", "error"):
        async def _immediate():
            yield f"data: {json.dumps({'event': 'scan_complete', 'data': state.to_summary_dict()})}\n\n"
            # Also replay all existing findings for late-joining clients
            for fd in state.findings:
                yield f"data: {json.dumps({'event': 'finding', 'data': {'finding': fd}})}\n\n"
        return StreamingResponse(_immediate(), media_type="text/event-stream")

    async def _generate():
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=25.0)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue

                if item is None:  # sentinel — stream is done
                    break

                yield f"data: {json.dumps(item)}\n\n"
        finally:
            try:
                state.sse_queues.remove(queue)
            except ValueError:
                pass

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}/findings", response_model=List[Dict])
async def get_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity (e.g. HIGH)"),
    category: Optional[str] = Query(None),
    judge_type: Optional[str] = Query(None),
    vulnerable_only: bool = Query(False),
    search: Optional[str] = Query(None, description="Search payload_id or prompt text"),
):
    """Return findings for a scan, with optional filters."""
    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    results = list(state.findings)

    if severity:
        results = [f for f in results if f.get("severity", "").upper() == severity.upper()]
    if category:
        results = [f for f in results if f.get("category", "").lower() == category.lower()]
    if judge_type:
        results = [f for f in results if f.get("judge_type", "").lower() == judge_type.lower()]
    if vulnerable_only:
        results = [f for f in results if f.get("vulnerable")]
    if search:
        q = search.lower()
        results = [
            f for f in results
            if q in f.get("payload_id", "").lower()
            or q in f.get("prompt", "").lower()
            or q in f.get("category", "").lower()
        ]

    return results


@router.get("/{scan_id}/report/html")
async def get_html_report(scan_id: str):
    """Serve the generated HTML report file."""
    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    report_path = state.output_dir / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="HTML report not yet generated")
    return FileResponse(str(report_path), media_type="text/html")


@router.get("/{scan_id}/report/json")
async def get_json_report(scan_id: str):
    """Serve the generated JSON report file."""
    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    report_path = state.output_dir / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="JSON report not yet generated")
    return FileResponse(
        str(report_path),
        media_type="application/json",
        filename=f"scan_{scan_id[:8]}_report.json",
    )


@router.post("/{scan_id}/retest", response_model=Dict[str, Any])
async def retest_payload_in_scan(scan_id: str, request: RetestPayloadRequest):
    """Retest a single security payload/prompt against the target endpoint and re-evaluate judge verdict."""
    from scanner.models import Payload
    from scanner.adapters.rest_adapter import RESTAdapter
    from scanner.converters.registry import get_converter
    from scanner.engine import ScanEngine

    state = get_scan(scan_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    cfg = state.config

    # Find existing finding in state.findings
    target_idx = -1
    existing_finding_dict: Optional[Dict[str, Any]] = None
    for idx, f_dict in enumerate(state.findings):
        p_id = str(f_dict.get("payload_id") or f_dict.get("payload", {}).get("id", ""))
        conv = f_dict.get("converter_used")
        if p_id == request.payload_id:
            if request.converter_used is not None:
                if conv == request.converter_used:
                    target_idx = idx
                    existing_finding_dict = f_dict
                    break
            else:
                target_idx = idx
                existing_finding_dict = f_dict
                break

    prompt_text = request.prompt
    category = "prompt_injection"
    owasp_id = "LLM01"
    severity = "HIGH"
    converter_name = request.converter_used

    if existing_finding_dict:
        if not prompt_text:
            prompt_text = (
                existing_finding_dict.get("original_prompt")
                or existing_finding_dict.get("prompt")
                or existing_finding_dict.get("payload", {}).get("prompt", "")
            )
        category = existing_finding_dict.get("category") or existing_finding_dict.get("payload", {}).get("category", category)
        owasp_id = existing_finding_dict.get("owasp_id") or existing_finding_dict.get("payload", {}).get("owasp_id", owasp_id)
        severity = existing_finding_dict.get("severity") or existing_finding_dict.get("payload", {}).get("severity", severity)
        if not converter_name:
            converter_name = existing_finding_dict.get("converter_used")

    if not prompt_text:
        raise HTTPException(status_code=400, detail="Prompt text could not be identified for retest.")

    # Initialize Adapter
    if getattr(cfg, "target_type", "rest") == "browser":
        from scanner.adapters.browser_adapter import (
            BrowserAdapter,
            DEFAULT_INPUT_SELECTOR,
            DEFAULT_SUBMIT_SELECTOR,
            DEFAULT_RESPONSE_SELECTOR,
        )
        adapter = BrowserAdapter(
            target_url=cfg.target_url,
            input_selector=cfg.input_selector or DEFAULT_INPUT_SELECTOR,
            send_button_selector=cfg.send_button_selector or DEFAULT_SUBMIT_SELECTOR,
            response_selector=cfg.response_selector or DEFAULT_RESPONSE_SELECTOR,
            wait_for_response_timeout=cfg.wait_for_response_timeout or 10.0,
            login_config=cfg.login_config,
        )
    else:
        body_template = cfg.body_template or (
            '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
        )
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if cfg.auth_header:
            if ":" in cfg.auth_header:
                h_key, h_val = cfg.auth_header.split(":", 1)
                headers[h_key.strip()] = h_val.strip()
            else:
                headers["Authorization"] = cfg.auth_header.strip()

        adapter = RESTAdapter(
            url=cfg.target_url,
            body_template=body_template,
            response_field=cfg.response_field,
            headers=headers,
        )

    try:
        engine = ScanEngine(
            adapter=adapter,
            delay=0.0,
            concurrency=1,
            use_llm_judge=cfg.use_llm_judge,
            ollama_url=cfg.ollama_url,
            judge_model=cfg.judge_model,
        )

        payload = Payload(
            id=request.payload_id,
            category=category,
            owasp_id=owasp_id,
            prompt=prompt_text,
            severity=severity,
            requires_llm_judge=cfg.use_llm_judge,
        )

        prompt_to_send = prompt_text
        if converter_name:
            try:
                converter_inst = get_converter(converter_name)
                prompt_to_send = await converter_inst.transform(prompt_text)
            except Exception as conv_err:
                logger.warning(f"Failed to transform retest prompt with converter '{converter_name}': {conv_err}")

        new_finding = await engine._send_and_judge(payload, prompt_to_send, converter_name=converter_name)
        new_finding_dict = _finding_to_dict(new_finding)

        # Update finding in state.findings if present
        if target_idx >= 0:
            state.findings[target_idx] = new_finding_dict
        else:
            state.findings.append(new_finding_dict)

        # Recalculate stats
        state.vulnerable_count = sum(1 for f in state.findings if f.get("vulnerable"))
        state.total_target_tokens = sum(f.get("target_prompt_tokens", 0) + f.get("target_completion_tokens", 0) for f in state.findings)
        state.total_tokens = sum(f.get("total_tokens", 0) for f in state.findings)

        # Broadcast SSE retest event for live updates
        state.broadcast_sse("retest_complete", {"payload_id": request.payload_id, "finding": new_finding_dict})

        return new_finding_dict
    finally:
        if getattr(cfg, "target_type", "rest") == "browser":
            try:
                await adapter.close()
            except Exception:
                pass
