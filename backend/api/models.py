"""Pydantic request/response models for the LLM Sentinel Dashboard API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Scan request / response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Body for POST /api/scans."""

    target_type: str = Field(
        "rest",
        description="Target type: 'rest' (REST API endpoint) | 'browser' (Playwright web form / chat UI)",
    )
    target_url: str = Field(..., description="Target LLM API or Web Page URL")

    # REST Adapter fields
    body_template: Optional[str] = Field(
        None,
        description=(
            'JSON body template with {{PROMPT}} placeholder. '
            'Defaults to Ollama chat format if omitted.'
        ),
    )
    response_field: str = Field(
        "message.content",
        description="Dotted-path key to extract model response text (for REST targets)",
    )
    auth_header: Optional[str] = Field(
        None,
        description="Optional Authorization header value (e.g. 'Bearer my-key')",
    )

    # Browser Adapter fields
    input_selector: Optional[str] = Field(
        None,
        description="CSS selector for the chat input textbox (for browser targets)",
    )
    send_button_selector: Optional[str] = Field(
        None,
        description="CSS selector for the Send/Submit button (for browser targets)",
    )
    response_selector: Optional[str] = Field(
        None,
        description="CSS selector for the assistant's rendered reply container (for browser targets)",
    )
    wait_for_response_timeout: Optional[float] = Field(
        10.0,
        ge=1.0,
        description="Seconds to wait for model response to render in browser (default 10.0s)",
    )
    login_config: Optional[Dict[str, str]] = Field(
        None,
        description="Optional login config: username_selector, username_value, password_selector, password_value, login_button_selector",
    )

    # Attack orchestration settings
    packs: Optional[List[str]] = Field(
        None,
        description="Payload pack names to load (e.g. ['owasp_llm01', 'owasp_llm07']). "
                    "Loads all packs if omitted.",
    )
    scan_mode: str = Field(
        "single",
        description="Attack mode: 'single' | 'multiturn' | 'converter'",
    )
    max_turns: int = Field(4, ge=1, le=8, description="Max turns for multi-turn mode")
    converters: Optional[List[str]] = Field(
        None,
        description="Converter names to apply in converter mode (e.g. ['base64', 'leetspeak'])",
    )
    use_llm_judge: bool = Field(
        False, description="Enforce LLM judge for all payload evaluations"
    )
    judge_model: str = Field("qwen2.5:3b", description="Ollama model name for LLM judge")
    ollama_url: str = Field(
        "http://localhost:11434/api/chat",
        description="Ollama API endpoint URL",
    )
    delay: float = Field(0.0, ge=0, description="Delay in seconds between requests")
    concurrency: int = Field(5, ge=1, le=20, description="Max simultaneous requests")
    limit: Optional[int] = Field(
        None, ge=1, description="Limit to first N payloads (None = all)"
    )


class ScanSummary(BaseModel):
    """Lightweight summary included in list/status responses."""

    scan_id: str
    status: str  # pending | running | done | error
    target_type: str = "rest"  # rest | browser
    scan_mode: str
    target_url: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    progress: int = 0
    total: int = 0
    vulnerable_count: int = 0
    total_payloads: int = 0
    posture_score: Optional[float] = None
    grade: Optional[str] = None
    circuit_broken: bool = False
    error_message: Optional[str] = None
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    likert_distribution: Dict[str, int] = Field(default_factory=dict)
    category_scores: Dict[str, float] = Field(default_factory=dict)
    duration_seconds: Optional[float] = None
    total_target_tokens: int = 0
    total_judge_tokens: int = 0
    total_tokens: int = 0
    judge_tokens_saved: int = 0


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Browser Selector Validation (Health-Check)
# ---------------------------------------------------------------------------

class BrowserTestSelectorsRequest(BaseModel):
    target_url: str = Field(..., description="Target webpage URL to validate")
    input_selector: str = Field(..., description="CSS selector for chat input textbox")
    send_button_selector: Optional[str] = Field(
        None,
        description="CSS selector for send button",
    )
    response_selector: Optional[str] = Field(
        None,
        description="CSS selector for response element",
    )
    wait_for_response_timeout: Optional[float] = Field(
        10.0,
        description="Page timeout in seconds",
    )
    login_config: Optional[Dict[str, str]] = Field(
        None,
        description="Optional login config dictionary",
    )


class BrowserTestSelectorsResponse(BaseModel):
    ok: bool
    url: str
    selectors: Dict[str, Any]
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------

class FindingResponse(BaseModel):
    """Serialized finding for the /findings endpoint."""

    payload_id: str
    category: str
    owasp_id: str
    prompt: str
    sent_prompt: Optional[str]
    response_text: str
    vulnerable: bool
    severity: str
    confidence: float
    judge_type: str
    reasoning: str
    error: Optional[str]
    converter_used: Optional[str]
    original_prompt: Optional[str]
    likert_score: int
    target_prompt_tokens: int = 0
    target_completion_tokens: int = 0
    judge_prompt_tokens: int = 0
    judge_completion_tokens: int = 0
    total_tokens: int = 0
    # Multi-turn extras (None for single-turn findings)
    succeeded_at_turn: Optional[int] = None
    full_transcript: Optional[List[Dict[str, Any]]] = None
    attack_strategy: Optional[str] = None
    breached_vulnerabilities: Optional[List[str]] = None
    breach_factors: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Payload pack schema
# ---------------------------------------------------------------------------

class PayloadPackInfo(BaseModel):
    name: str
    category: str
    owasp_id: str
    count: int
    file_path: str
    sample_payload: Optional[Dict[str, Any]] = None
    source: Optional[str] = None
    is_community: bool = False


# ---------------------------------------------------------------------------
# Community Import schemas
# ---------------------------------------------------------------------------

class CommunityPreviewRequest(BaseModel):
    raw_text: Optional[str] = Field(
        None, description="Raw text pasted by user (JSON, CSV, or line-separated text)"
    )


class CommunityPreviewResponse(BaseModel):
    detected_format: str  # 'csv' | 'json' | 'txt'
    columns: Optional[List[str]] = None
    sample_rows: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int
    suggested_mapping: Dict[str, str] = Field(default_factory=dict)
    raw_text: Optional[str] = None


class CommunityConvertRequest(BaseModel):
    source_data: Optional[Any] = Field(
        None, description="Raw row dicts or line list extracted during preview"
    )
    raw_text: Optional[str] = Field(
        None, description="Full raw source text content if available"
    )
    max_records: Optional[int] = Field(
        None, description="Max payloads to convert (None or 0 = ALL)"
    )
    detected_format: str = Field(..., description="'csv' | 'json' | 'txt'")
    field_mapping: Dict[str, str] = Field(
        default_factory=dict,
        description="User-confirmed mapping: schema_field -> source_column",
    )
    default_category: str = Field("Community Payload Import", description="Default category")
    default_owasp_id: str = Field("LLM01", description="Default OWASP ID")
    default_severity: str = Field("HIGH", description="Default severity")
    default_expected_vulnerable: Optional[bool] = Field(
        True, description="Default expected_vulnerable ground truth"
    )


class CommunityConvertResponse(BaseModel):
    yaml_content: str
    total_count: int


class CommunitySaveRequest(BaseModel):
    pack_name: str = Field(
        ..., description="Desired payload pack name (alphanumeric + underscore/hyphen)"
    )
    yaml_content: str = Field(..., description="Generated YAML string")
    confirmed_large_import: bool = Field(
        False, description="Flag acknowledging import of >500 payloads"
    )


class CommunitySaveResponse(BaseModel):
    status: str
    pack_name: str
    output_path: str
    count: int
    message: str



# ---------------------------------------------------------------------------
# Dataset endpoints
# ---------------------------------------------------------------------------

class DatasetImportRequest(BaseModel):
    csv_path: str = Field(..., description="Server-side path to behaviors CSV file")
    label: str = Field(
        "harmful",
        description="Label for behaviors: 'harmful' | 'benign'",
    )
    output_pack_name: str = Field(
        "imported_behaviors",
        description="Output YAML pack filename stem",
    )
    output_dir: Optional[str] = Field(
        None,
        description="Directory to write the converted YAML pack. Defaults to scanner/payloads/handwritten/",
    )


class DatasetImportResponse(BaseModel):
    status: str
    rows_imported: int
    output_path: str
    message: str


class EvalJudgeRequest(BaseModel):
    csv_path: str = Field(..., description="Server-side path to judge-comparison.csv")
    sample_size: Optional[int] = Field(None, ge=1, description="Random sample size")
    ollama_url: str = Field("http://localhost:11434/api/chat")
    judge_model: str = Field("qwen2.5:3b")
    timeout: float = Field(30.0)
    output_dir: Optional[str] = Field(None)


class RetestPayloadRequest(BaseModel):
    payload_id: str = Field(..., description="Payload ID to retest (e.g. 'LLM01-001')")
    prompt: Optional[str] = Field(None, description="Optional custom prompt text override")
    converter_used: Optional[str] = Field(None, description="Optional converter name to apply")


class EvalJudgeResponse(BaseModel):
    status: str
    summary: Dict[str, Any]
    benchmarks: Dict[str, Any]
    report_path: str
