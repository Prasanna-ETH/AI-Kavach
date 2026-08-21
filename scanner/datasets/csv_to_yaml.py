"""YAML converter for JailbreakBench behavior datasets."""

import logging
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
import yaml

logger = logging.getLogger("scanner.datasets")


def build_payload_dict(
    payload_id: str,
    prompt: str,
    category: str = "prompt_injection",
    owasp_id: str = "LLM01",
    severity: str = "HIGH",
    heuristic_keywords: Optional[List[str]] = None,
    requires_llm_judge: bool = True,
    expected_vulnerable: Optional[bool] = None,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct and validate a payload dictionary matching scanner YAML schema.

    Args:
        payload_id: Unique payload identifier.
        prompt: Raw prompt text.
        category: Vulnerability category string.
        owasp_id: OWASP Top 10 category code (e.g. 'LLM01').
        severity: Severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO').
        heuristic_keywords: Keywords to look for in response.
        requires_llm_judge: Flag indicating if LLM judge is required.
        expected_vulnerable: Ground truth label (True/False/None).
        source: Benchmark or dataset origin.

    Returns:
        Payload dictionary object matching repo schema.
    """
    clean_prompt = prompt.strip() if prompt else ""
    if not clean_prompt:
        raise ValueError("Payload prompt text cannot be empty.")

    item: Dict[str, Any] = {
        "id": payload_id,
        "category": category.strip() if category else "prompt_injection",
        "owasp_id": owasp_id.strip().upper() if owasp_id else "LLM01",
        "prompt": clean_prompt,
        "severity": severity.strip().upper() if severity else "HIGH",
        "heuristic_keywords": heuristic_keywords or [],
        "requires_llm_judge": bool(requires_llm_judge),
    }

    if expected_vulnerable is not None:
        item["expected_vulnerable"] = bool(expected_vulnerable)
    if source is not None:
        item["source"] = str(source).strip()

    return item


def generate_yaml_string(payload_dicts: List[Dict[str, Any]]) -> str:
    """Generate formatted YAML string from a list of payload dictionaries."""
    data = {"payloads": payload_dicts}
    return yaml.dump(data, default_flow_style=False, sort_keys=False, width=1000, allow_unicode=True)


def convert_behaviors_to_payloads(
    rows: List[Dict[str, str]],
    category: str = "jailbreak",
    owasp_id: str = "LLM01",
    expected_vulnerable: bool = True,
    label: str = None,
) -> List[Dict[str, Any]]:
    """Map CSV row dicts into payload dictionaries matching scanner YAML schema.

    Args:
        rows: List of behavior CSV row dictionaries.
        category: Vulnerability category string (default 'jailbreak').
        owasp_id: OWASP Top 10 category code (default 'LLM01').
        expected_vulnerable: True for harmful behaviors, False for benign.
        label: Optional string 'harmful' or 'benign' to override expected_vulnerable.

    Returns:
        List of payload dictionary objects.
    """
    if label is not None:
        expected_vulnerable = (label.strip().lower() != "benign")

    prefix = "H" if expected_vulnerable else "B"
    severity = "HIGH" if expected_vulnerable else "INFO"
    payloads: List[Dict[str, Any]] = []

    for idx_num, row in enumerate(rows, start=1):
        idx = row.get("Index", str(idx_num)).strip()
        goal = row.get("Goal", "").strip()
        if not goal:
            continue
        source_val = row.get("Source", "").strip()
        cat_val = row.get("Category", "").strip()

        source_str = f"{source_val} / {cat_val}" if source_val and cat_val else (source_val or cat_val)

        item = build_payload_dict(
            payload_id=f"JBB-{prefix}-{idx}",
            prompt=goal,
            category=category,
            owasp_id=owasp_id,
            severity=severity,
            heuristic_keywords=[],
            requires_llm_judge=True,
            expected_vulnerable=expected_vulnerable,
            source=source_str or "JailbreakBench",
        )
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

    yaml_text = generate_yaml_string(payload_dicts)
    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml_text)

    logger.info(f"Saved {len(payload_dicts)} payloads to YAML file: {path.resolve()}")
    return path

