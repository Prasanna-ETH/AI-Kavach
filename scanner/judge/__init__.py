"""Judge module for evaluating target responses for security vulnerabilities."""

from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.llm_judge import LLMJudge

__all__ = ["HeuristicJudge", "LLMJudge"]
