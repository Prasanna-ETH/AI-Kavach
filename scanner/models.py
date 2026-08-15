"""Data models for payloads, scan findings, execution results, and multi-turn conversations."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class Payload:
    """Represents a security attack payload to be sent to an LLM endpoint.

    Attributes:
        id: Unique payload identifier (e.g., PI-001).
        category: Vulnerability category name (e.g., prompt_injection).
        owasp_id: Mapped OWASP LLM Top 10 category code (e.g., LLM01).
        prompt: The attack prompt text sent to the target model.
        severity: Expected vulnerability severity level (LOW, MEDIUM, HIGH, CRITICAL).
        heuristic_keywords: List of keywords or regex patterns to detect in response.
        requires_llm_judge: Whether an LLM judge is required/recommended.
    """
    id: str
    category: str
    owasp_id: str
    prompt: str
    severity: str
    heuristic_keywords: List[str] = field(default_factory=list)
    requires_llm_judge: bool = False
    expected_vulnerable: Optional[bool] = None
    source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert Payload instance to dictionary."""
        d = {
            "id": self.id,
            "category": self.category,
            "owasp_id": self.owasp_id,
            "prompt": self.prompt,
            "severity": self.severity,
            "heuristic_keywords": self.heuristic_keywords,
            "requires_llm_judge": self.requires_llm_judge,
        }
        if self.expected_vulnerable is not None:
            d["expected_vulnerable"] = self.expected_vulnerable
        if self.source is not None:
            d["source"] = self.source
        return d


@dataclass
class Finding:
    """Represents the evaluation result of running a payload against a target.

    Attributes:
        payload: The Payload instance tested.
        response_text: Raw text extracted from the target's response.
        vulnerable: Flag indicating if vulnerability was detected.
        severity: Assigned severity rating.
        confidence: Confidence score (0.0 to 1.0).
        judge_type: Evaluation mechanism used ('heuristic', 'llm', or 'none').
        reasoning: Explanation for why payload was flagged or passed.
        error: Error message if request or evaluation failed.
    """
    payload: Payload
    response_text: str
    vulnerable: bool
    severity: str
    confidence: float = 1.0
    judge_type: str = "heuristic"
    reasoning: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert Finding instance to dictionary."""
        return {
            "payload": self.payload.to_dict(),
            "response_text": self.response_text,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "confidence": self.confidence,
            "judge_type": self.judge_type,
            "reasoning": self.reasoning,
            "error": self.error,
        }


@dataclass
class ScanResult:
    """Represents complete scan results for a security audit run.

    Attributes:
        target_url: The API endpoint URL scanned.
        start_time: ISO-8601 formatted start timestamp.
        end_time: ISO-8601 formatted end timestamp.
        total_payloads: Total number of payloads executed.
        findings: List of Finding results.
        circuit_broken: Indicates whether scan stopped prematurely due to failures.
        duration_seconds: Scan execution duration in seconds.
    """
    target_url: str
    start_time: str
    end_time: str
    total_payloads: int
    findings: List[Finding] = field(default_factory=list)
    circuit_broken: bool = False
    duration_seconds: float = 0.0

    @property
    def vulnerable_count(self) -> int:
        """Count total findings flagged as vulnerable."""
        return sum(1 for f in self.findings if f.vulnerable)

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Return counts of vulnerable findings broken down by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.vulnerable:
                sev = f.severity.upper()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts[sev] = 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanResult instance to dictionary."""
        return {
            "target_url": self.target_url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_payloads": self.total_payloads,
            "vulnerable_count": self.vulnerable_count,
            "severity_counts": self.severity_counts,
            "circuit_broken": self.circuit_broken,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ConversationTurn:
    """Represents a single message exchange in a multi-turn conversation.

    Attributes:
        turn_number: 1-based index of the dialogue turn.
        role: "attacker" (red-team prompt) or "target" (model response).
        content: Message text.
        timestamp: Epoch timestamp of message creation.
    """
    turn_number: int
    role: str
    content: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert ConversationTurn instance to dictionary."""
        return {
            "turn_number": self.turn_number,
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
        }


@dataclass
class MultiTurnPayload:
    """Represents a multi-turn adversarial scenario.

    Attributes:
        id: Unique identifier (e.g., MT-001).
        category: Vulnerability category name.
        owasp_id: OWASP Top 10 for LLM Applications ID.
        severity: Severity rating.
        max_turns: Maximum conversation turns allowed (default 4).
        opening_prompt: Initial prompt sent in turn 1.
        escalation_strategy: Instruction for Attacker LLM strategy across turns.
        stop_condition_hint: Description of what constitutes success for the judge.
    """
    id: str
    category: str
    owasp_id: str
    severity: str
    opening_prompt: str
    escalation_strategy: str
    stop_condition_hint: str
    max_turns: int = 4

    def to_dict(self) -> Dict[str, Any]:
        """Convert MultiTurnPayload instance to dictionary."""
        return {
            "id": self.id,
            "category": self.category,
            "owasp_id": self.owasp_id,
            "severity": self.severity,
            "max_turns": self.max_turns,
            "opening_prompt": self.opening_prompt,
            "escalation_strategy": self.escalation_strategy,
            "stop_condition_hint": self.stop_condition_hint,
        }


@dataclass
class MultiTurnFinding:
    """Represents the evaluation outcome of a multi-turn attack scenario.

    Attributes:
        payload_id: MultiTurnPayload ID.
        category: Vulnerability category.
        owasp_id: Mapped OWASP ID.
        vulnerable: Flag indicating if vulnerability was successfully exploited.
        severity: Severity rating assigned.
        confidence: Confidence score (0.0 to 1.0).
        reasoning: Explanation for evaluation outcome.
        full_transcript: Ordered list of ConversationTurn exchanges.
        succeeded_at_turn: Turn number where vulnerability first appeared (or None).
        error: Error details if execution failed.
    """
    payload_id: str
    category: str
    owasp_id: str
    vulnerable: bool
    severity: str
    confidence: float
    reasoning: str
    full_transcript: List[ConversationTurn] = field(default_factory=list)
    succeeded_at_turn: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert MultiTurnFinding instance to dictionary."""
        return {
            "payload_id": self.payload_id,
            "category": self.category,
            "owasp_id": self.owasp_id,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "succeeded_at_turn": self.succeeded_at_turn,
            "error": self.error,
            "full_transcript": [t.to_dict() for t in self.full_transcript],
        }
