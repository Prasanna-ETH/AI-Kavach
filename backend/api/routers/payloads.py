"""Payload packs router — list available YAML payload packs with metadata.

GET /api/payload-packs
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, HTTPException

from backend.api.models import PayloadPackInfo

logger = logging.getLogger("sentinel.api.payloads")

router = APIRouter(prefix="/api/payload-packs", tags=["payloads"])

# Root of the payloads directory (relative to project root, resolved at startup)
_PAYLOADS_DIR = Path(__file__).parents[3] / "scanner" / "payloads"


def _owasp_id_from_stem(stem: str) -> str:
    """Derive a best-effort OWASP ID from the YAML filename stem."""
    stem_lower = stem.lower()
    if "system_prompt" in stem_lower or "llm07" in stem_lower:
        return "LLM07"
    if "sensitive" in stem_lower or "data_leak" in stem_lower or "llm02" in stem_lower:
        return "LLM02"
    if "insecure_output" in stem_lower or "exfil" in stem_lower or "llm10" in stem_lower:
        return "LLM10"
    if "jailbreak" in stem_lower or "prompt_injection" in stem_lower or "multiturn" in stem_lower or "evasion" in stem_lower or "llm01" in stem_lower:
        return "LLM01"
    if "llm08" in stem_lower:
        return "LLM08"
    if "llm06" in stem_lower:
        return "LLM06"
    for tag in ("llm01", "llm02", "llm03", "llm04", "llm05",
                "llm06", "llm07", "llm08", "llm09", "llm10"):
        if tag in stem_lower:
            return tag.upper()
    return "LLM01"


def _category_from_stem(stem: str) -> str:
    """Derive a human-friendly category from the YAML filename stem."""
    category_map = {
        "prompt_injection": "Prompt Injection",
        "jailbreak": "Safety Jailbreak",
        "multiturn": "Multi-Turn Social Engineering",
        "evasion": "Evasion Obfuscation Converters",
        "sensitive": "Sensitive Data Leakage",
        "system_prompt": "System Prompt Leakage",
        "insecure_output": "Insecure Output Handling / Exfiltration",
        "exfil": "Insecure Output Handling / Exfiltration",
        "llm01": "Prompt Injection & Safety Jailbreak",
        "llm02": "Sensitive Data Leakage",
        "llm06": "Excessive Agency / Privilege Escalation",
        "llm07": "System Prompt Leakage",
        "llm08": "Vector & Output Exploitation",
        "llm09": "Misinformation / Hallucination",
        "llm10": "Insecure Output Handling / Exfiltration",
    }
    stem_lower = stem.lower()
    for key, label in category_map.items():
        if key in stem_lower:
            return label
    return stem.replace("_", " ").title()


def _load_pack_info(filepath: Path) -> Optional[PayloadPackInfo]:
    """Parse a YAML payload pack and return a PayloadPackInfo or None on error."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "payloads" not in data:
            return None

        payloads_list: List[Dict[str, Any]] = data["payloads"]
        count = len(payloads_list)
        if count == 0:
            return None

        sample: Optional[Dict[str, Any]] = None
        for item in payloads_list:
            if not isinstance(item, dict):
                continue
            prompt_val = (
                item.get("prompt") or 
                item.get("opening_prompt") or 
                item.get("attack_prompt") or 
                item.get("instruction") or 
                item.get("text") or 
                item.get("attack") or 
                item.get("vector") or 
                item.get("payload") or 
                item.get("description")
            )
            if prompt_val:
                sample = {
                    "id": str(item.get("id", item.get("payload_id", f"{filepath.stem}-01"))),
                    "category": str(item.get("category", _category_from_stem(filepath.stem))),
                    "owasp_id": str(item.get("owasp_id", _owasp_id_from_stem(filepath.stem))),
                    "severity": str(item.get("severity", "HIGH")),
                    "prompt": str(prompt_val)[:400],
                    "requires_llm_judge": bool(item.get("requires_llm_judge", False)),
                }
                break
        
        # Fallback if no specific prompt key matched
        if not sample and payloads_list:
            first_item = payloads_list[0]
            if isinstance(first_item, dict):
                first_str = next((str(v) for v in first_item.values() if isinstance(v, str) and len(str(v)) > 5), f"Security test vector pack: {filepath.stem}")
                sample = {
                    "id": str(first_item.get("id", f"{filepath.stem}-01")),
                    "category": _category_from_stem(filepath.stem),
                    "owasp_id": _owasp_id_from_stem(filepath.stem),
                    "severity": str(first_item.get("severity", "HIGH")),
                    "prompt": first_str[:400],
                    "requires_llm_judge": False,
                }

        # Disambiguate duplicate stems (e.g. dataset_50 in different folders)
        stem = filepath.stem
        rel_str = str(filepath).lower()
        if stem == "dataset_50":
            if "jbb" in rel_str:
                stem = "jbb_jailbreak_50"
            elif "handwritten" in rel_str:
                stem = "handwritten_quick_50"

        # Derive OWASP ID: Check stem first for accurate classification
        owasp_id = _owasp_id_from_stem(stem)

        # Detect community origin from payload items or file path
        source_val: Optional[str] = None
        is_community = False
        if "community" in rel_str:
            is_community = True
            source_val = "community-import"

        for item in payloads_list:
            item_source = str(item.get("source", ""))
            if item_source:
                if not source_val:
                    source_val = item_source
                if "community" in item_source.lower():
                    is_community = True
                    source_val = item_source
                    break

        return PayloadPackInfo(
            name=stem,
            category=_category_from_stem(stem),
            owasp_id=owasp_id,
            count=count,
            file_path=str(filepath.relative_to(_PAYLOADS_DIR.parent.parent)),
            sample_payload=sample,
            source=source_val,
            is_community=is_community,
        )
    except Exception as exc:
        logger.warning(f"Failed to parse payload pack {filepath}: {exc}")
        return None


@router.get("", response_model=List[PayloadPackInfo])
async def list_payload_packs():
    """Return metadata for all available YAML payload packs."""
    if not _PAYLOADS_DIR.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Payloads directory not found: {_PAYLOADS_DIR}",
        )

    packs: List[PayloadPackInfo] = []
    for filepath in sorted(_PAYLOADS_DIR.rglob("*.yaml")):
        info = _load_pack_info(filepath)
        if info is not None:
            packs.append(info)

    return packs
