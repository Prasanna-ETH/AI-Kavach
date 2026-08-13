"""JSON report generator for CI/CD consumption."""

import json
from pathlib import Path
from typing import Union

from scanner.models import ScanResult


def generate_json_report(result: ScanResult, output_path: Union[str, Path]) -> Path:
    """Export scan results as structured JSON to file.

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
