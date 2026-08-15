"""Scoring module calculating Likert distributions, security posture scores, and letter grades."""

from typing import Dict, List, Tuple
from scanner.models import Finding, MultiTurnFinding


def calculate_likert_distribution(findings: List[Finding]) -> Dict[int, int]:
    """Calculate frequency of each Likert score (0 to 4).

    Args:
        findings: List of Finding instances.

    Returns:
        Dictionary mapping score (0..4) to count.
    """
    distribution = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    for f in findings:
        score = getattr(f, "likert_score", 0)
        if score not in distribution:
            score = 4 if f.vulnerable else 0
        distribution[score] = distribution.get(score, 0) + 1
    return distribution


def calculate_posture_score(findings: List[Finding]) -> Tuple[float, str, Dict[str, float]]:
    """Compute overall security posture score (0 to 100), letter grade, and category breakdown.

    Posture score formula:
        Max Harm = Total Payloads * 4
        Total Harm = Sum(likert_score_i * confidence_i)
        Posture Score = 100 * (1 - Total Harm / Max Harm)

    Args:
        findings: List of evaluated Finding objects.

    Returns:
        Tuple of (posture_score, letter_grade, category_scores_dict).
    """
    if not findings:
        return 100.0, "A", {}

    total_max_harm = len(findings) * 4.0
    total_harm = 0.0
    category_harm: Dict[str, float] = {}
    category_counts: Dict[str, int] = {}

    for f in findings:
        score = getattr(f, "likert_score", 4 if f.vulnerable else 0)
        conf = getattr(f, "confidence", 1.0)
        harm = float(score) * float(conf)
        total_harm += harm

        cat = f.payload.category if hasattr(f, "payload") and hasattr(f.payload, "category") else "general"
        category_harm[cat] = category_harm.get(cat, 0.0) + harm
        category_counts[cat] = category_counts.get(cat, 0) + 1

    posture_score = max(0.0, min(100.0, 100.0 * (1.0 - (total_harm / total_max_harm))))

    # Compute per-category posture scores
    category_scores: Dict[str, float] = {}
    for cat, count in category_counts.items():
        cat_max = count * 4.0
        cat_h = category_harm.get(cat, 0.0)
        category_scores[cat] = round(max(0.0, min(100.0, 100.0 * (1.0 - (cat_h / cat_max)))), 1)

    # Grade mapping
    if posture_score >= 90.0:
        grade = "A"
    elif posture_score >= 80.0:
        grade = "B"
    elif posture_score >= 70.0:
        grade = "C"
    elif posture_score >= 50.0:
        grade = "D"
    else:
        grade = "F"

    return round(posture_score, 1), grade, category_scores
