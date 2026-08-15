"""Unit tests for dataset ingestion, conversion, and judge evaluation logic."""

import tempfile
from pathlib import Path
import pytest

from scanner.datasets.csv_loader import load_behaviors_csv, load_judge_comparison_csv
from scanner.datasets.csv_to_yaml import convert_behaviors_to_payloads, save_payloads_to_yaml
from scanner.models import Finding, Payload
from scanner.report.eval_report import compute_eval_metrics, generate_eval_report


VALID_BEHAVIORS_CSV = """Index,Goal,Target,Behavior,Category,Source
0,Goal text 0,Target text 0,Behavior 0,Category 0,Source 0
1,Goal text 1,Target text 1,Behavior 1,Category 1,Source 1
"""

MISSING_COL_BEHAVIORS_CSV = """Index,Goal,Target,Behavior,Category
0,Goal text 0,Target text 0,Behavior 0,Category 0
"""

VALID_JUDGE_COMPARISON_CSV = """Index,goal,prompt,target_response,human1,human2,human3,human_majority,harmbench_cf,gpt4_cf,llamaguard2_cf,llama3_cf
0,goal 0,prompt 0,target resp 0,0,0,0,0,0,0,0,0
1,goal 1,prompt 1,target resp 1,1,1,1,1,1,1,1,1
"""

INVALID_HUMAN_MAJ_CSV = """Index,goal,prompt,target_response,human1,human2,human3,human_majority,harmbench_cf,gpt4_cf,llamaguard2_cf,llama3_cf
0,goal 0,prompt 0,target resp 0,0,0,0,INVALID,0,0,0,0
"""


def test_load_behaviors_csv_valid(tmp_path: Path) -> None:
    csv_file = tmp_path / "behaviors.csv"
    csv_file.write_text(VALID_BEHAVIORS_CSV, encoding="utf-8")

    rows = load_behaviors_csv(csv_file)
    assert len(rows) == 2
    assert rows[0]["Index"] == "0"
    assert rows[0]["Goal"] == "Goal text 0"
    assert rows[1]["Source"] == "Source 1"


def test_load_behaviors_csv_missing_column(tmp_path: Path) -> None:
    csv_file = tmp_path / "invalid_behaviors.csv"
    csv_file.write_text(MISSING_COL_BEHAVIORS_CSV, encoding="utf-8")

    with pytest.raises(ValueError, match="missing required column: 'Source'"):
        load_behaviors_csv(csv_file)


def test_load_judge_comparison_csv_valid(tmp_path: Path) -> None:
    csv_file = tmp_path / "judge.csv"
    csv_file.write_text(VALID_JUDGE_COMPARISON_CSV, encoding="utf-8")

    rows = load_judge_comparison_csv(csv_file)
    assert len(rows) == 2
    assert rows[0]["human_majority"] is False
    assert rows[1]["human_majority"] is True


def test_load_judge_comparison_csv_invalid_human_majority(tmp_path: Path) -> None:
    csv_file = tmp_path / "invalid_judge.csv"
    csv_file.write_text(INVALID_HUMAN_MAJ_CSV, encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid 'human_majority' value"):
        load_judge_comparison_csv(csv_file)


def test_convert_behaviors_to_payloads() -> None:
    rows = [
        {"Index": "0", "Goal": "Attack Goal 1", "Source": "Original", "Category": "Defamation"},
        {"Index": "1", "Goal": "Attack Goal 2", "Source": "HarmBench", "Category": "Cyber"},
    ]

    # Harmful
    harmful_payloads = convert_behaviors_to_payloads(rows, category="jailbreak", owasp_id="LLM01", expected_vulnerable=True)
    assert len(harmful_payloads) == 2
    assert harmful_payloads[0]["id"] == "JBB-H-0"
    assert harmful_payloads[0]["prompt"] == "Attack Goal 1"
    assert harmful_payloads[0]["severity"] == "HIGH"
    assert harmful_payloads[0]["expected_vulnerable"] is True
    assert harmful_payloads[0]["source"] == "Original / Defamation"

    # Benign
    benign_payloads = convert_behaviors_to_payloads(rows, category="jailbreak", owasp_id="LLM01", expected_vulnerable=False)
    assert len(benign_payloads) == 2
    assert benign_payloads[0]["id"] == "JBB-B-0"
    assert benign_payloads[0]["severity"] == "INFO"
    assert benign_payloads[0]["expected_vulnerable"] is False


def test_save_payloads_to_yaml(tmp_path: Path) -> None:
    payload_dicts = [
        {
            "id": "JBB-H-0",
            "category": "jailbreak",
            "owasp_id": "LLM01",
            "prompt": "Test Prompt",
            "severity": "HIGH",
            "heuristic_keywords": [],
            "requires_llm_judge": True,
            "source": "Original / Test",
            "expected_vulnerable": True,
        }
    ]
    out_yaml = tmp_path / "test_out.yaml"
    saved_path = save_payloads_to_yaml(payload_dicts, out_yaml)
    assert saved_path.exists()
    content = saved_path.read_text(encoding="utf-8")
    assert "JBB-H-0" in content
    assert "Test Prompt" in content


def test_compute_eval_metrics() -> None:
    sample_payload = Payload(id="P1", category="c", owasp_id="o", prompt="p", severity="HIGH")

    # Construct mock dataset results:
    # Row 0: Pred True, GT True -> TP
    # Row 1: Pred True, GT False -> FP
    # Row 2: Pred False, GT False -> TN
    # Row 3: Pred False, GT True -> FN
    eval_results = [
        {
            "row": {"Index": "0", "goal": "g0", "prompt": "p0", "target_response": "r0", "harmbench_cf": "1"},
            "finding": Finding(payload=sample_payload, response_text="r0", vulnerable=True, severity="HIGH"),
            "human_majority": True,
        },
        {
            "row": {"Index": "1", "goal": "g1", "prompt": "p1", "target_response": "r1", "harmbench_cf": "0"},
            "finding": Finding(payload=sample_payload, response_text="r1", vulnerable=True, severity="HIGH"),
            "human_majority": False,
        },
        {
            "row": {"Index": "2", "goal": "g2", "prompt": "p2", "target_response": "r2", "harmbench_cf": "0"},
            "finding": Finding(payload=sample_payload, response_text="r2", vulnerable=False, severity="HIGH"),
            "human_majority": False,
        },
        {
            "row": {"Index": "3", "goal": "g3", "prompt": "p3", "target_response": "r3", "harmbench_cf": "1"},
            "finding": Finding(payload=sample_payload, response_text="r3", vulnerable=False, severity="HIGH"),
            "human_majority": True,
        },
    ]

    metrics = compute_eval_metrics(eval_results)
    summary = metrics["summary"]

    assert summary["total_samples"] == 4
    assert summary["true_positives"] == 1
    assert summary["false_positives"] == 1
    assert summary["true_negatives"] == 1
    assert summary["false_negatives"] == 1
    assert summary["accuracy"] == 0.5
    assert summary["precision"] == 0.5
    assert summary["recall"] == 0.5
    assert summary["f1_score"] == 0.5
    assert len(metrics["false_positives"]) == 1
    assert len(metrics["false_negatives"]) == 1
    assert metrics["false_positives"][0]["index"] == "1"
    assert metrics["false_negatives"][0]["index"] == "3"
