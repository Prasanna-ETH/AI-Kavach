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
    for tag in ("llm01", "llm02", "llm03", "llm04", "llm05",
                "llm06", "llm07", "llm08", "llm09", "llm10"):
        if tag in stem_lower:
            return tag.upper()
    return "LLM01"


def _category_from_stem(stem: str) -> str:
    """Derive a human-friendly category from the YAML filename stem."""
    category_map = {
        "llm01": "Prompt Injection",
        "llm02": "Sensitive Information Disclosure",
        "llm06": "Excessive Agency / Privilege Escalation",
        "llm07": "System Prompt Leakage",
        "llm08": "Vector & Embedding Weaknesses",
        "llm09": "Misinformation / Hallucination",
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
        for item in payloads_list[:3]:
            if "prompt" in item or "opening_prompt" in item:
                sample = {
                    "id": str(item.get("id", "?")),
                    "category": str(item.get("category", filepath.stem)),
                    "owasp_id": str(item.get("owasp_id", _owasp_id_from_stem(filepath.stem))),
                    "severity": str(item.get("severity", "HIGH")),
                    "prompt": str(
                        item.get("prompt", item.get("opening_prompt", ""))
                    )[:300],
                    "requires_llm_judge": bool(item.get("requires_llm_judge", False)),
                }
                break

        # Derive owasp_id: prefer first payload's field, else filename heuristic
        owasp_id = (
            str(payloads_list[0].get("owasp_id", ""))
            if payloads_list
            else _owasp_id_from_stem(filepath.stem)
        )
        if not owasp_id:
            owasp_id = _owasp_id_from_stem(filepath.stem)

        # Detect community origin from payload items or file path
        source_val: Optional[str] = None
        is_community = False
        if "community" in str(filepath).lower():
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
            name=filepath.stem,
            category=_category_from_stem(filepath.stem),
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
