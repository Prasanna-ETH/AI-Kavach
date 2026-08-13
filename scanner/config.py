"""Configuration loader for YAML payload packs."""

from pathlib import Path
from typing import List, Optional, Set
import yaml

from scanner.models import Payload


PAYLOADS_DIR = Path(__file__).parent / "payloads"


def load_payloads(
    pack_names: Optional[List[str]] = None,
    custom_dir: Optional[Path] = None,
) -> List[Payload]:
    """Load payloads from YAML files matching pack names.

    Args:
        pack_names: List of pack category names (e.g. ['prompt_injection', 'jailbreak']).
                    If None or empty, loads all available payload packs.
        custom_dir: Path to custom directory containing YAML packs.

    Returns:
        List of loaded Payload model instances.

    Raises:
        FileNotFoundError: If payloads directory does not exist.
        ValueError: If YAML syntax is invalid.
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
        if selected_packs and stem not in selected_packs:
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if not data or "payloads" not in data:
                    continue

                for item in data["payloads"]:
                    payload = Payload(
                        id=str(item["id"]),
                        category=str(item.get("category", stem)),
                        owasp_id=str(item.get("owasp_id", "LLM01")),
                        prompt=str(item["prompt"]),
                        severity=str(item.get("severity", "HIGH")).upper(),
                        heuristic_keywords=[str(k) for k in item.get("heuristic_keywords", [])],
                        requires_llm_judge=bool(item.get("requires_llm_judge", False)),
                    )
                    payloads.append(payload)
        except yaml.YAMLError as err:
            raise ValueError(f"Failed to parse payload YAML file '{filepath}': {err}") from err

    return payloads
