"""Configuration loader for YAML single-turn and multi-turn payload packs."""

from pathlib import Path
from typing import List, Optional, Set
import yaml

from scanner.models import MultiTurnPayload, Payload

PAYLOADS_DIR = Path(__file__).parent / "payloads"


def load_payloads(
    pack_names: Optional[List[str]] = None,
    custom_dir: Optional[Path] = None,
) -> List[Payload]:
    """Load single-turn payloads from YAML files matching pack names.

    Args:
        pack_names: List of pack category names (e.g. ['prompt_injection', 'jailbreak']).
                    If None or empty, loads all available single-turn payload packs.
        custom_dir: Path to custom directory containing YAML packs.

    Returns:
        List of loaded Payload model instances.
    """
    target_dir = custom_dir or PAYLOADS_DIR
    if not target_dir.exists():
        raise FileNotFoundError(f"Payloads directory not found: {target_dir}")

    selected_packs: Optional[Set[str]] = None
    if pack_names:
        selected_packs = {p.strip().lower().replace(".yaml", "") for p in pack_names}

    payloads: List[Payload] = []
    yaml_files = sorted(target_dir.glob("*.yaml"))

    for filepath in yaml_files:
        stem = filepath.stem.lower()
        if stem.startswith("multiturn"):
            continue

        if selected_packs and stem not in selected_packs:
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data or "payloads" not in data:
                    continue

                for item in data["payloads"]:
                    if "prompt" not in item:
                        continue
                    expected_vuln = item.get("expected_vulnerable")
                    payload = Payload(
                        id=str(item["id"]),
                        category=str(item.get("category", stem)),
                        owasp_id=str(item.get("owasp_id", "LLM01")),
                        prompt=str(item["prompt"]),
                        severity=str(item.get("severity", "HIGH")).upper(),
                        heuristic_keywords=[str(k) for k in item.get("heuristic_keywords", [])],
                        requires_llm_judge=bool(item.get("requires_llm_judge", False)),
                        expected_vulnerable=bool(expected_vuln) if expected_vuln is not None else None,
                        source=str(item["source"]) if "source" in item and item["source"] is not None else None,
                    )
                    payloads.append(payload)
        except yaml.YAMLError as err:
            raise ValueError(f"Failed to parse payload YAML file '{filepath}': {err}") from err

    return payloads


def load_multiturn_payloads(
    pack_names: Optional[List[str]] = None,
    custom_dir: Optional[Path] = None,
) -> List[MultiTurnPayload]:
    """Load multi-turn attack payloads from YAML files matching pack names.

    Args:
        pack_names: List of multi-turn pack names (e.g. ['multiturn_jailbreak']).
        custom_dir: Path to custom directory.

    Returns:
        List of MultiTurnPayload model instances.
    """
    target_dir = custom_dir or PAYLOADS_DIR
    if not target_dir.exists():
        raise FileNotFoundError(f"Payloads directory not found: {target_dir}")

    selected_packs: Optional[Set[str]] = None
    if pack_names:
        selected_packs = {p.strip().lower().replace(".yaml", "") for p in pack_names}

    payloads: List[MultiTurnPayload] = []
    yaml_files = sorted(target_dir.glob("multiturn*.yaml"))

    if not yaml_files:
        yaml_files = sorted(target_dir.glob("*.yaml"))

    for filepath in yaml_files:
        stem = filepath.stem.lower()
        if selected_packs and stem not in selected_packs:
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data or "payloads" not in data:
                    continue

                for item in data["payloads"]:
                    if "opening_prompt" not in item:
                        continue
                    mt_payload = MultiTurnPayload(
                        id=str(item["id"]),
                        category=str(item.get("category", stem)),
                        owasp_id=str(item.get("owasp_id", "LLM06")),
                        severity=str(item.get("severity", "HIGH")).upper(),
                        max_turns=int(item.get("max_turns", 4)),
                        opening_prompt=str(item["opening_prompt"]),
                        escalation_strategy=str(item.get("escalation_strategy", "")),
                        stop_condition_hint=str(item.get("stop_condition_hint", "")),
                    )
                    payloads.append(mt_payload)
        except yaml.YAMLError as err:
            raise ValueError(f"Failed to parse multi-turn payload YAML '{filepath}': {err}") from err

    return payloads
