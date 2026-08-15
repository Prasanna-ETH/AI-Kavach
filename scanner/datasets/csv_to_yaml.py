"""YAML converter for JailbreakBench behavior datasets."""

import logging
from pathlib import Path
from typing import List, Dict, Any, Union
import yaml

logger = logging.getLogger("scanner.datasets")


def convert_behaviors_to_payloads(
    rows: List[Dict[str, str]],
    category: str = "jailbreak",
    owasp_id: str = "LLM01",
    expected_vulnerable: bool = True,
) -> List[Dict[str, Any]]:
    """Map CSV row dicts into payload dictionaries matching scanner YAML schema.

    Args:
        rows: List of behavior CSV row dictionaries.
        category: Vulnerability category string (default 'jailbreak').
        owasp_id: OWASP Top 10 category code (default 'LLM01').
        expected_vulnerable: True for harmful behaviors, False for benign.

    Returns:
        List of payload dictionary objects.
    """
    prefix = "H" if expected_vulnerable else "B"
    severity = "HIGH" if expected_vulnerable else "INFO"
    payloads: List[Dict[str, Any]] = []

    for row in rows:
        idx = row.get("Index", "").strip()
        goal = row.get("Goal", "").strip()
        source_val = row.get("Source", "").strip()
        cat_val = row.get("Category", "").strip()

        source_str = f"{source_val} / {cat_val}" if source_val and cat_val else (source_val or cat_val)

        item = {
            "id": f"JBB-{prefix}-{idx}",
            "category": category,
            "owasp_id": owasp_id,
            "prompt": goal,
            "severity": severity,
            "heuristic_keywords": [],
            "requires_llm_judge": True,
            "source": source_str,
            "expected_vulnerable": expected_vulnerable,
        }
        payloads.append(item)

    logger.info(f"Converted {len(payloads)} behavior rows into payload dictionaries (expected_vulnerable={expected_vulnerable})")
    return payloads


def save_payloads_to_yaml(
    payload_dicts: List[Dict[str, Any]],
    output_path: Union[str, Path],
) -> Path:
    """Save payload dictionaries to YAML file matching repo schema.

    Args:
        payload_dicts: List of payload dictionary objects.
        output_path: Path string or Path object to destination YAML file.

    Returns:
        Path object pointing to written YAML file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {"payloads": payload_dicts}
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=1000, allow_unicode=True)

    logger.info(f"Saved {len(payload_dicts)} payloads to YAML file: {path.resolve()}")
    return path
