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
        "name": "Prompt Injection & Filter Evasion",
        "description": "Crafted inputs that manipulate LLMs to bypass system guardrails, alter intended behavior, or execute unauthorized instructions.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Sensitive Information & PII Disclosure",
        "description": "Unintended disclosure of confidential user data, passwords, SSNs, credit cards, proprietary business data, or API keys.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/",
    },
    "LLM03": {
        "id": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "description": "Risks stemming from third-party pre-trained models, vulnerable plugins, training data pipelines, or compromised packages.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm02-supply-chain/",
    },
    "LLM04": {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "description": "Manipulation of training data or fine-tuning datasets to introduce backdoors, biases, or security degradation.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm03-data-and-model-poisoning/",
    },
    "LLM05": {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "description": "Failure to sanitize model output before passing it to downstream interpreters, web frontends, or automated agents.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Excessive Agency & Jailbreak Bypasses",
        "description": "Coercing the model into assuming unauthorized personas (e.g. DAN, Developer Mode) or granting unchecked tool invocation permissions.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm08-excessive-agency/",
    },
    "LLM07": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "description": "Tricking the model into disclosing its internal developer preamble, confidential system instructions, or backend prompt architecture.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
    "LLM08": {
        "id": "LLM08",
        "name": "Insecure Output Handling (XSS / SQLi / Exfil)",
        "description": "Generating raw scripts, malicious Markdown image exfiltration links, or unescaped commands executed in consumer environments.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    "LLM09": {
        "id": "LLM09",
        "name": "Overreliance & Hallucination Risk",
        "description": "Excessive reliance on unverified model outputs resulting in security misinformation or erroneous code execution.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm09-overreliance/",
    },
    "LLM10": {
        "id": "LLM10",
        "name": "Model Denial of Service",
        "description": "Resource-heavy queries or context-bombing attacks causing high compute latency, memory exhaustion, or service downtime.",
        "reference_url": "https://genai.owasp.org/llmrisk/llm10-model-denial-of-service/",
    },
    "NONE": {
        "id": "NONE",
        "name": "Benign Functional Baseline",
        "description": "Standard non-adversarial user queries used for false-positive validation and baseline performance measuring.",
        "reference_url": "https://genai.owasp.org/",
    },
}

CATEGORY_TO_OWASP: Dict[str, str] = {
    "prompt_injection": "LLM01",
    "sensitive_data_leak": "LLM02",
    "jailbreak": "LLM06",
    "system_prompt_leak": "LLM07",
    "insecure_output": "LLM08",
    "benign": "NONE",
}


def get_owasp_info(category_or_id: str) -> OWASPInfo:
    """Retrieve OWASP taxonomy info by category name or OWASP ID.

    Args:
        category_or_id: Category key (e.g. 'prompt_injection') or OWASP ID (e.g. 'LLM01').

    Returns:
        OWASPInfo typed dict.
    """
    owasp_id = CATEGORY_TO_OWASP.get(category_or_id.lower(), category_or_id.upper())
    return OWASP_LLM_TOP_10.get(
        owasp_id,
        {
            "id": owasp_id,
            "name": f"{owasp_id} Category",
            "description": "Security risk evaluation category.",
            "reference_url": "https://genai.owasp.org/",
        },
    )
