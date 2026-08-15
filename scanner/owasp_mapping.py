"""Mapping internal vulnerability categories to OWASP Top 10 for LLM Applications."""

from typing import Dict, TypedDict


class OWASPInfo(TypedDict):
    id: str
    name: str
    description: str
    reference_url: str


OWASP_LLM_TOP_10: Dict[str, OWASPInfo] = {
    "LLM01": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to bypass safety rules or execute unauthorized actions.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "description": "Revealing confidential data, secrets, or internal API keys in LLM output.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/",
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Excessive Agency / Jailbreak",
        "description": "Bypassing safety alignment and guardrails to generate harmful, restricted, or unfiltered output.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm08-excessive-agency/",
    },
    "LLM07": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "description": "Tricking the model into disclosing its system instructions, internal prompts, or operational constraints.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
}

CATEGORY_TO_OWASP: Dict[str, str] = {
    "prompt_injection": "LLM01",
    "sensitive_data_leak": "LLM02",
    "jailbreak": "LLM06",
    "system_prompt_leak": "LLM07",
}


def get_owasp_info(category_or_id: str) -> OWASPInfo:
    """Retrieve OWASP taxonomy info by category name or OWASP ID.

    Args:
        category_or_id: Category key (e.g. 'prompt_injection') or OWASP ID (e.g. 'LLM01').

    Returns:
        OWASPInfo typed dict.
    """
    owasp_id = CATEGORY_TO_OWASP.get(category_or_id, category_or_id)
    return OWASP_LLM_TOP_10.get(
        owasp_id,
        {
            "id": owasp_id,
            "name": "Other LLM Vulnerability",
            "description": "Unclassified LLM security risk.",
            "reference_url": "https://genai.owasp.org/",
        },
    )
