"""In-memory scan registry for the LLM Sentinel Dashboard API.

Stores scan state, live findings, SSE queues, and final results.
No external database required — designed for local hackathon demo use.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.api.models import ScanRequest


# ---------------------------------------------------------------------------
# Scan state dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanState:
    """Runtime state for a single scan run."""

    scan_id: str
    config: ScanRequest
    status: str = "pending"          # pending | running | done | error
    progress: int = 0
    total: int = 0
    vulnerable_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    result_dict: Optional[Dict[str, Any]] = None   # populated on completion
    circuit_broken: bool = False
    error_message: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    posture_score: Optional[float] = None
    grade: Optional[str] = None
    severity_counts: Dict[str, int] = field(default_factory=dict)
    likert_distribution: Dict[str, int] = field(default_factory=dict)
    category_scores: Dict[str, float] = field(default_factory=dict)
    total_target_tokens: int = 0
    total_judge_tokens: int = 0
    total_tokens: int = 0
    judge_tokens_saved: int = 0

    # SSE: each connected frontend client gets its own asyncio.Queue
    sse_queues: List[asyncio.Queue] = field(default_factory=list)

    @property
    def output_dir(self) -> Path:
        return Path("scan_results") / self.scan_id

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "target_type": getattr(self.config, "target_type", "rest"),
            "scan_mode": self.config.scan_mode,
            "target_url": self.config.target_url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "progress": self.progress,
            "total": self.total,
            "vulnerable_count": self.vulnerable_count,
            "total_payloads": self.total,
            "posture_score": self.posture_score,
            "grade": self.grade,
            "circuit_broken": self.circuit_broken,
            "error_message": self.error_message,
            "severity_counts": self.severity_counts,
            "likert_distribution": self.likert_distribution,
            "category_scores": self.category_scores,
            "duration_seconds": self.duration_seconds,
            "total_target_tokens": self.total_target_tokens,
            "total_judge_tokens": self.total_judge_tokens,
            "total_tokens": self.total_tokens,
            "judge_tokens_saved": self.judge_tokens_saved,
        }

    def broadcast_sse(self, event_type: str, data: Dict[str, Any]) -> None:
        """Put an SSE event dict onto every connected client's queue (non-blocking)."""
        payload = {"event": event_type, "data": data}
        for q in list(self.sse_queues):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass  # slow consumer — drop the event rather than block


# ---------------------------------------------------------------------------
# Global registry (module-level singleton for the demo)
# ---------------------------------------------------------------------------

_scans: Dict[str, ScanState] = {}


def create_scan(config: ScanRequest) -> ScanState:
    """Allocate a new ScanState, register it, and return it."""
    scan_id = str(uuid.uuid4())
    state = ScanState(scan_id=scan_id, config=config)
    _scans[scan_id] = state
    return state


def get_scan(scan_id: str) -> Optional[ScanState]:
    return _scans.get(scan_id)


def list_scans() -> List[ScanState]:
    """Return all scans, most-recent first (by insertion order preserved in Python 3.7+)."""
    return list(reversed(list(_scans.values())))
