"""KAVACH-PoF Step 2: Static & AST Analyzer for System Prompts and Backend Code."""

from typing import Dict, Any, List
import re
import logging

logger = logging.getLogger("kavach.crs.static_analyzer")

class StaticAnalyzer:
    """Analyzes AST pattern rules, system prompt guardrails, and API boundary definitions."""

    def analyze_system_prompt(self, prompt_text: str) -> Dict[str, Any]:
        """Perform static analysis on system instructions to detect over-privileged or leaky prompts."""
        vulnerabilities = []
        
        if re.search(r"sk-test|password|secret_key|api_key", prompt_text, re.IGNORECASE):
            vulnerabilities.append({
                "type": "Hardcoded Secrets in System Prompt",
                "severity": "CRITICAL",
                "recommendation": "Remove plaintext credentials from LLM system prompt context."
            })
            
        if not re.search(r"do not disclose|never reveal|confidential", prompt_text, re.IGNORECASE):
            vulnerabilities.append({
                "type": "Missing Explicit Refusal Boundary Directive",
                "severity": "HIGH",
                "recommendation": "Add explicit refusal guardrail directives."
            })
            
        logger.info(f"[KAVACH-StaticAnalyzer] Analysis complete: {len(vulnerabilities)} vulnerabilities identified.")
        return {
            "prompt_length": len(prompt_text),
            "vulnerabilities": vulnerabilities,
            "passed": len(vulnerabilities) == 0
        }
