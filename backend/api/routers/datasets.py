"""Dataset tools router.

POST /api/datasets/import      → wraps load_behaviors_csv + convert + save YAML
POST /api/datasets/eval-judge  → wraps load_judge_comparison_csv + judge eval + compute_eval_metrics
"""

from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from backend.api.models import (
    DatasetImportRequest,
    DatasetImportResponse,
    EvalJudgeRequest,
    EvalJudgeResponse,
)

logger = logging.getLogger("sentinel.api.datasets")

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


@router.post("/import", response_model=DatasetImportResponse)
async def import_behaviors(request: DatasetImportRequest):
    """
    Import a JailbreakBench-format behaviors CSV and convert it to a YAML
    payload pack usable by the scanner engine.

    Calls into existing scanner.datasets and scanner.datasets.csv_to_yaml modules.
    """
    from scanner.datasets.csv_loader import load_behaviors_csv
    from scanner.datasets.csv_to_yaml import convert_behaviors_to_payloads, save_payloads_to_yaml

    csv_path = Path(request.csv_path)
    if not csv_path.exists():
        raise HTTPException(status_code=400, detail=f"CSV file not found: {csv_path}")

    try:
        rows = load_behaviors_csv(csv_path)
    except (FileNotFoundError, ValueError) as err:
        raise HTTPException(status_code=400, detail=str(err))

    try:
        payloads = convert_behaviors_to_payloads(
            rows=rows,
            label=request.label,
        )
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Conversion failed: {err}")

    # Determine output directory
    if request.output_dir:
        out_dir = Path(request.output_dir)
    else:
        import os
        from scanner.config import PAYLOADS_DIR as _DEFAULT_PAYLOADS_DIR
        _p_dir = Path(os.environ.get("PAYLOADS_DIR", str(_DEFAULT_PAYLOADS_DIR)))
        if not _p_dir.exists():
            _p_dir = Path(__file__).parents[3] / "scanner" / "payloads"
        out_dir = _p_dir / "handwritten"

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{request.output_pack_name}.yaml"

    try:
        save_payloads_to_yaml(payloads=payloads, output_path=out_path)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to save YAML: {err}")

    return DatasetImportResponse(
        status="success",
        rows_imported=len(payloads),
        output_path=str(out_path.resolve()),
        message=f"Imported {len(payloads)} payloads from '{csv_path.name}' → '{out_path.name}'",
    )


@router.post("/eval-judge", response_model=EvalJudgeResponse)
async def eval_judge(request: EvalJudgeRequest):
    """
    Evaluate heuristic + LLM judge accuracy against a JailbreakBench
    judge-comparison CSV. Returns precision/recall/F1/confusion matrix.

    Calls into existing scanner.datasets, scanner.judge, and
    scanner.report.eval_report modules without duplicating any logic.
    """
    from scanner.datasets.csv_loader import load_judge_comparison_csv
    from scanner.judge.heuristics import HeuristicJudge
    from scanner.judge.llm_judge import LLMJudge, check_ollama_available, FALLBACK_JUDGE_TYPE
    from scanner.models import Payload
    from scanner.report.eval_report import compute_eval_metrics, generate_eval_report

    csv_path = Path(request.csv_path)
    if not csv_path.exists():
        raise HTTPException(status_code=400, detail=f"CSV file not found: {csv_path}")

    try:
        rows = load_judge_comparison_csv(csv_path)
    except (FileNotFoundError, ValueError) as err:
        raise HTTPException(status_code=400, detail=str(err))

    if request.sample_size and request.sample_size < len(rows):
        rows = random.sample(rows, request.sample_size)

    # Health check for Ollama before starting a potentially long eval
    available, health_msg = await check_ollama_available(
        ollama_url=request.ollama_url,
        model=request.judge_model,
        timeout=request.timeout,
    )
    if not available:
        raise HTTPException(
            status_code=503,
            detail=f"LLM Judge unavailable: {health_msg}. Start Ollama and ensure '{request.judge_model}' is pulled.",
        )

    heuristic_judge = HeuristicJudge()
    llm_judge = LLMJudge(
        ollama_url=request.ollama_url,
        model=request.judge_model,
        timeout=request.timeout,
    )

    async def _run_eval() -> List[Dict[str, Any]]:
        results = []
        for row in rows:
            payload = Payload(
                id=f"JBB-EVAL-{row['Index']}",
                category="jailbreak",
                owasp_id="LLM01",
                prompt=str(row["prompt"]),
                severity="HIGH",
                requires_llm_judge=True,
            )
            response_text = str(row["target_response"])
            finding = await heuristic_judge.evaluate(payload, response_text)
            if not finding.vulnerable:
                finding = await llm_judge.evaluate(payload, response_text)
            results.append({
                "row": row,
                "finding": finding,
                "human_majority": row["human_majority"],
            })
        return results

    try:
        eval_results = await _run_eval()
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {err}")

    try:
        # compute_eval_metrics may accept model_name kwarg (newer versions)
        try:
            metrics = compute_eval_metrics(eval_results, model_name=request.judge_model)
        except TypeError:
            metrics = compute_eval_metrics(eval_results)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Metrics computation failed: {err}")

    # Save report to output dir
    if request.output_dir:
        out_dir = Path(request.output_dir)
    else:
        out_dir = Path("scan_results") / "eval_judge"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "judge_eval_report.json"

    try:
        generate_eval_report(metrics, report_path)
    except Exception as err:
        logger.warning(f"Could not save eval report: {err}")

    return EvalJudgeResponse(
        status="success",
        summary=metrics.get("summary", {}),
        benchmarks=metrics.get("benchmarks", {}),
        report_path=str(report_path.resolve()),
    )
