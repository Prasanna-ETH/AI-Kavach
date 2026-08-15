"""JSON report generator for CI/CD consumption."""

import json
from pathlib import Path
from typing import List, Union

from scanner.models import MultiTurnFinding, ScanResult


def generate_json_report(result: ScanResult, output_path: Union[str, Path]) -> Path:
    """Export single-turn scan results as structured JSON to file.

    Args:
        result: ScanResult model instance.
        output_path: Path string or Path object destination.

    Returns:
        Path object pointing to generated JSON file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    return path


def generate_multiturn_json_report(findings: List[MultiTurnFinding], output_path: Union[str, Path]) -> Path:
    """Export multi-turn attack findings as structured JSON to file.

    Args:
        findings: List of MultiTurnFinding objects.
        output_path: Path string or Path object destination.

    Returns:
        Path object pointing to generated JSON file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "scan_type": "multi_turn_adversarial",
        "total_payloads": len(findings),
        "vulnerable_count": sum(1 for f in findings if f.vulnerable),
        "findings": [f.to_dict() for f in findings],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path
