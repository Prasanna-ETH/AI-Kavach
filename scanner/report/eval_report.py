"""Judge evaluation report generator saving metrics, FP/FN analysis, and benchmark comparisons to JSON."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Union

logger = logging.getLogger("scanner.report")


def compute_eval_metrics(
    eval_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute accuracy, precision, recall, F1, and confusion matrix from evaluation results.

    Args:
        eval_results: List of dicts, each containing:
            - 'row': raw judge comparison CSV row
            - 'finding': Finding instance produced by judge
            - 'human_majority': bool ground truth label

    Returns:
        Dict containing metrics summary, false positives, false negatives, and benchmark comparison.
    """
    total = len(eval_results)
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []

    # Benchmark accuracy counters for comparison automated judges
    benchmark_counts = {
        "harmbench_cf": 0,
        "gpt4_cf": 0,
        "llamaguard2_cf": 0,
        "llama3_cf": 0,
    }
    benchmark_totals = {
        "harmbench_cf": 0,
        "gpt4_cf": 0,
        "llamaguard2_cf": 0,
        "llama3_cf": 0,
    }

    for item in eval_results:
        row = item["row"]
        finding = item["finding"]
        ground_truth = item["human_majority"]
        predicted = finding.vulnerable

        if predicted and ground_truth:
            tp += 1
        elif predicted and not ground_truth:
            fp += 1
            false_positives.append({
                "index": row.get("Index"),
                "goal": row.get("goal"),
                "prompt": row.get("prompt"),
                "target_response": row.get("target_response"),
                "judge_type": finding.judge_type,
                "reasoning": finding.reasoning,
            })
        elif not predicted and not ground_truth:
            tn += 1
        else:
            fn += 1
            false_negatives.append({
                "index": row.get("Index"),
                "goal": row.get("goal"),
                "prompt": row.get("prompt"),
                "target_response": row.get("target_response"),
                "judge_type": finding.judge_type,
                "reasoning": finding.reasoning,
            })

        # Calculate benchmark judge agreement
        gt_int = 1 if ground_truth else 0
        for col in benchmark_counts:
            val_str = str(row.get(col, "")).strip()
            if val_str in ("0", "1"):
                benchmark_totals[col] += 1
                if int(val_str) == gt_int:
                    benchmark_counts[col] += 1

    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    benchmarks: Dict[str, Any] = {}
    for col, count in benchmark_counts.items():
        tot = benchmark_totals[col]
        benchmarks[col] = {
            "accuracy": round(count / tot, 4) if tot > 0 else 0.0,
            "correct": count,
            "total": tot,
        }

    return {
        "summary": {
            "total_samples": total,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        },
        "benchmarks": benchmarks,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def generate_eval_report(
    eval_metrics: Dict[str, Any],
    output_path: Union[str, Path] = "scan_results/judge_eval_report.json",
) -> Path:
    """Save judge evaluation report metrics to JSON file.

    Args:
        eval_metrics: Dict returned by compute_eval_metrics().
        output_path: Destination JSON path.

    Returns:
        Path object pointing to saved JSON file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(eval_metrics, f, indent=2)

    logger.info(f"Saved judge evaluation report to {path.resolve()}")
    return path
