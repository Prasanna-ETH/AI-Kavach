"""KAVACH-PoF: Evidence-Gated Autonomous Cyber Reasoning System (CRS).

Theme: Defensive by Design
Competition: AI Kavach Cyber Challenge 2026

Core Pipeline: Discover -> Understand -> Repair -> Verify -> Prove
"""

from crs.fuzzer import AutonomousFuzzer
from crs.static_analyzer import StaticAnalyzer
from crs.patch_generator import AutonomousPatchGenerator
from crs.test_harness import RegressionTestHarness
from crs.evidence_verifier import ProofOfFixVerifier, ProofOfFixArtifact

__version__ = "1.0.0-kavach"
__all__ = [
    "AutonomousFuzzer",
    "StaticAnalyzer",
    "AutonomousPatchGenerator",
    "RegressionTestHarness",
    "ProofOfFixVerifier",
    "ProofOfFixArtifact",
]
