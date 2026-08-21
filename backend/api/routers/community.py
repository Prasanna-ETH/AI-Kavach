"""Community payload import router.

Endpoints:
POST /api/payloads/community/preview  → Auto-detect format & suggest mappings
POST /api/payloads/community/convert  → Build Payload objects and generate YAML preview string
POST /api/payloads/community/save     → Sanitize name, validate batch size, and write YAML to scanner/payloads/community/
"""

from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, Request

from backend.api.models import (
    CommunityConvertRequest,
    CommunityConvertResponse,
    CommunityPreviewRequest,
    CommunityPreviewResponse,
    CommunitySaveRequest,
    CommunitySaveResponse,
)
from scanner.datasets.csv_to_yaml import build_payload_dict, generate_yaml_string

logger = logging.getLogger("sentinel.api.community")

router = APIRouter(prefix="/api/payloads/community", tags=["community-payloads"])

# Root of payloads directory
_PAYLOADS_DIR = Path(__file__).parents[3] / "scanner" / "payloads"
_COMMUNITY_DIR = _PAYLOADS_DIR / "community"


def _suggest_mappings(columns: List[str]) -> Dict[str, str]:
    """Suggest column-to-schema field mappings using heuristic string matching."""
    mapping: Dict[str, str] = {}
    col_lower_map = {c.lower().strip(): c for c in columns}

    heuristics = {
        "prompt": ["prompt", "goal", "text", "attack", "input", "query", "user_input", "instruction", "payload", "harmful_prompt", "question"],
        "category": ["category", "type", "vulnerability", "cat", "class", "vulnerability_type"],
        "expected_vulnerable": ["label", "vulnerable", "expected_vulnerable", "is_jailbreak", "harmful", "target", "is_vulnerable"],
        "owasp_id": ["owasp", "owasp_id", "owasp_category", "owasp_code"],
        "severity": ["severity", "risk", "level", "priority"],
    }

    for schema_field, keywords in heuristics.items():
        for kw in keywords:
            if kw in col_lower_map:
                mapping[schema_field] = col_lower_map[kw]
                break

    # Default fallback for prompt if no match found
    if "prompt" not in mapping and columns:
        mapping["prompt"] = columns[0]

    return mapping


def _parse_tabular_rows(content: str) -> tuple[str, List[str], List[Dict[str, Any]], int]:
    """Try parsing content as CSV or JSON, returning (detected_format, columns, rows, total_count)."""
    clean_text = content.strip()
    if not clean_text:
        raise ValueError("Uploaded file or text content is empty.")

    # 1. Try JSON parsing
    if clean_text.startswith("[") or clean_text.startswith("{"):
        try:
            data = json.loads(clean_text)
            if isinstance(data, dict):
                # Look for common array container keys
                for key in ("payloads", "data", "rows", "items", "prompts", "behaviors", "attacks"):
                    if key in data and isinstance(data[key], list):
                        data = data[key]
                        break

            if isinstance(data, list):
                if not data:
                    raise ValueError("JSON array is empty.")

                # Case A: Array of Dicts
                if isinstance(data[0], dict):
                    cols_set: Dict[str, bool] = {}
                    for row in data:
                        if isinstance(row, dict):
                            for k in row.keys():
                                cols_set[str(k)] = True
                    columns = list(cols_set.keys())
                    return "json", columns, data, len(data)

                # Case B: Array of Strings
                elif isinstance(data[0], str):
                    rows = [{"prompt": str(item)} for item in data if str(item).strip()]
                    return "txt", ["prompt"], rows, len(rows)

        except json.JSONDecodeError:
            pass  # Fall through to CSV parsing

    # 2. Try CSV parsing
    lines = clean_text.splitlines()
    if len(lines) > 1 and ("," in lines[0] or "\t" in lines[0] or ";" in lines[0]):
        try:
            # Sniff delimiter
            sample_header = lines[0]
            delimiter = ","
            if "\t" in sample_header and "," not in sample_header:
                delimiter = "\t"
            elif ";" in sample_header and "," not in sample_header:
                delimiter = ";"

            reader = csv.DictReader(lines, delimiter=delimiter)
            rows = [dict(r) for r in reader if any(v.strip() for v in r.values() if v)]
            if rows and reader.fieldnames:
                columns = [str(f) for f in reader.fieldnames if f]
                return "csv", columns, rows, len(rows)
        except Exception as err:
            logger.debug(f"CSV parse attempt failed: {err}")

    # 3. Fallback: Plain text newline-separated prompts
    non_empty_lines = [line.strip() for line in lines if line.strip()]
    if not non_empty_lines:
        raise ValueError("No valid text lines or rows could be parsed.")

    rows = [{"prompt": line} for line in non_empty_lines]
    return "txt", ["prompt"], rows, len(rows)


@router.post("/preview", response_model=CommunityPreviewResponse)
async def preview_community_payloads(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
):
    """Auto-detect format (CSV/JSON/TXT) from file upload or raw pasted text, returning sample rows and suggested mappings."""
    text_content = ""

    if file is not None:
        try:
            raw_bytes = await file.read()
            text_content = raw_bytes.decode("utf-8", errors="replace")
        except Exception as err:
            raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {err}")
    elif raw_text and raw_text.strip():
        text_content = raw_text.strip()
    else:
        # Check if sent as JSON body
        try:
            body_json = await request.json()
            if isinstance(body_json, dict) and body_json.get("raw_text"):
                text_content = str(body_json["raw_text"]).strip()
        except Exception:
            pass

    if not text_content:
        raise HTTPException(
            status_code=400,
            detail="No source provided. Please upload a file (.csv, .json, .txt) or paste raw text.",
        )

    try:
        detected_format, columns, rows, total_count = _parse_tabular_rows(text_content)
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Failed to parse import content: {err}")

    sample_rows = rows[:5]
    suggested_mapping = _suggest_mappings(columns)

    return CommunityPreviewResponse(
        detected_format=detected_format,
        columns=columns,
        sample_rows=sample_rows,
        total_count=total_count,
        suggested_mapping=suggested_mapping,
        raw_text=text_content,
    )


@router.post("/convert", response_model=CommunityConvertResponse)
async def convert_community_payloads(request: CommunityConvertRequest):
    """Convert previewed source rows into Payload objects using shared schema validation, returning YAML preview string."""
    source_data: Optional[List[Any]] = None

    if request.raw_text and request.raw_text.strip():
        try:
            _, _, parsed_rows, _ = _parse_tabular_rows(request.raw_text.strip())
            source_data = parsed_rows
        except Exception as err:
            logger.warning(f"Failed to re-parse raw_text in convert: {err}")

    if not source_data:
        if isinstance(request.source_data, list):
            source_data = request.source_data

    if not source_data:
        raise HTTPException(status_code=400, detail="source_data or raw_text cannot be empty.")

    if request.max_records and request.max_records > 0:
        source_data = source_data[: request.max_records]

    field_mapping = request.field_mapping or {}
    prompt_col = field_mapping.get("prompt", "prompt")

    payload_dicts: List[Dict[str, Any]] = []

    if isinstance(source_data, list):
        for idx, item in enumerate(source_data, start=1):
            if isinstance(item, dict):
                # Extract prompt using field mapping or fallbacks
                prompt_val = str(
                    item.get(prompt_col)
                    or item.get("prompt")
                    or item.get("goal")
                    or item.get("text")
                    or item.get("input")
                    or ""
                ).strip()

                if not prompt_val:
                    continue  # Skip empty prompt rows

                # Extract category
                cat_col = field_mapping.get("category")
                category_val = str(item.get(cat_col) if cat_col else "").strip() or request.default_category

                # Extract owasp_id
                owasp_col = field_mapping.get("owasp_id")
                owasp_val = str(item.get(owasp_col) if owasp_col else "").strip() or request.default_owasp_id

                # Extract severity
                sev_col = field_mapping.get("severity")
                sev_val = str(item.get(sev_col) if sev_col else "").strip() or request.default_severity

                # Extract expected_vulnerable
                exp_col = field_mapping.get("expected_vulnerable")
                exp_val = request.default_expected_vulnerable
                if exp_col and exp_col in item:
                    raw_exp = item[exp_col]
                    if isinstance(raw_exp, bool):
                        exp_val = raw_exp
                    elif isinstance(raw_exp, (int, float)):
                        exp_val = bool(raw_exp)
                    elif isinstance(raw_exp, str):
                        s = raw_exp.strip().lower()
                        if s in ("true", "1", "harmful", "jailbreak", "yes", "vulnerable"):
                            exp_val = True
                        elif s in ("false", "0", "benign", "no", "safe"):
                            exp_val = False

                p_dict = build_payload_dict(
                    payload_id=f"COMM-{idx:03d}",
                    prompt=prompt_val,
                    category=category_val,
                    owasp_id=owasp_val,
                    severity=sev_val,
                    heuristic_keywords=[],
                    requires_llm_judge=True,
                    expected_vulnerable=exp_val,
                    source="community-import",
                )
                payload_dicts.append(p_dict)

            elif isinstance(item, str) and item.strip():
                p_dict = build_payload_dict(
                    payload_id=f"COMM-{idx:03d}",
                    prompt=item.strip(),
                    category=request.default_category,
                    owasp_id=request.default_owasp_id,
                    severity=request.default_severity,
                    heuristic_keywords=[],
                    requires_llm_judge=True,
                    expected_vulnerable=request.default_expected_vulnerable,
                    source="community-import",
                )
                payload_dicts.append(p_dict)

    if not payload_dicts:
        raise HTTPException(
            status_code=400,
            detail="No valid payloads could be constructed. Please verify that your prompt column mapping is correct.",
        )

    try:
        yaml_content = generate_yaml_string(payload_dicts)
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to generate YAML preview: {err}")

    return CommunityConvertResponse(
        yaml_content=yaml_content,
        total_count=len(payload_dicts),
    )


@router.post("/save", response_model=CommunitySaveResponse)
async def save_community_payload_pack(request: CommunitySaveRequest):
    """Sanitize pack name against path traversal, check batch size limit (>500), and write YAML pack to scanner/payloads/community/."""
    pack_name_raw = request.pack_name.strip()
    if not pack_name_raw:
        raise HTTPException(status_code=400, detail="Pack name cannot be empty.")

    # Sanitize pack name (alphanumeric, underscore, hyphen only)
    if not re.match(r"^[a-zA-Z0-9_-]+$", pack_name_raw) or ".." in pack_name_raw or "/" in pack_name_raw or "\\" in pack_name_raw:
        raise HTTPException(
            status_code=400,
            detail="Invalid pack name. Pack names must contain only alphanumeric characters, underscores, and hyphens.",
        )

    sanitized_name = pack_name_raw.lower()
    if not sanitized_name.startswith("community_"):
        file_stem = f"community_{sanitized_name}"
    else:
        file_stem = sanitized_name

    # Validate YAML content
    try:
        parsed_yaml = yaml.safe_load(request.yaml_content)
        if not isinstance(parsed_yaml, dict) or "payloads" not in parsed_yaml or not isinstance(parsed_yaml["payloads"], list):
            raise ValueError("YAML content missing 'payloads' root list.")
        count = len(parsed_yaml["payloads"])
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Invalid YAML content: {err}")

    # Check >500 payload limit
    if count > 500 and not request.confirmed_large_import:
        raise HTTPException(
            status_code=400,
            detail=f"Pack contains {count} payloads, exceeding the 500 payload threshold. Confirmation required.",
        )

    _COMMUNITY_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _COMMUNITY_DIR / f"{file_stem}.yaml"

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(request.yaml_content)
        logger.info(f"Successfully saved community payload pack: {out_path.resolve()}")
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to save payload pack: {err}")

    return CommunitySaveResponse(
        status="success",
        pack_name=file_stem,
        output_path=str(out_path.relative_to(_PAYLOADS_DIR.parent.parent)),
        count=count,
        message=f"Community payload pack '{file_stem}' saved successfully with {count} security test vectors.",
    )
