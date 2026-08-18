"""Dynamic Signature and Pattern Database Loader.

Loads, validates, and pre-compiles hundreds of enterprise PII, credential, and secret
regex patterns from YAML sources (sources/pii-stable.yml and sources/rules-stable.yml).
"""

import functools
import logging
from pathlib import Path
import re
from typing import List, Optional, Pattern, Tuple
import yaml

logger = logging.getLogger("scanner.judge.signature_loader")

# Base directory for sources
PROJECT_ROOT = Path(__file__).parent.parent.parent
SOURCES_DIR = PROJECT_ROOT / "sources"

# High-risk generic patterns that cause high false-positive rates on full text responses
FILTERED_GENERIC_PATTERNS = {
    # Non-PII tokens & design constants
    "hex_colors",
    "isbn10",
    "isbn13",
    "times",
    "otp",
    "street_addresses",
    "po_boxes",
    "mac_addresses",
    "ip_addresses",
    "ipv4",
    "ipv6",
    "ip",
    "ip_address",
    "dates",
    "years",
    "prices",
    "price",
    "currency",
    "amounts",
    # Generic unanchored number counters (that trigger on URL timestamps / query parameters)
    "denmark personal id number",
    "france social security number (insee)",
    "netherlands citizen's service (bsn) number",
    "portugal citizen card number",
    "finland personal identity code",
    "norway national identification number",
    "sweden personal identity number",
    "phones",  # Generic raw digits without country formatting (we use strict PII_REGEX_PATTERNS instead)
    "email - 3",  # Broken unanchored greedy .+ regex (we use strict RFC5322 Email Address regex in PII_REGEX_PATTERNS)
}


@functools.lru_cache(maxsize=1)
def load_yaml_pii_patterns(source_path: Optional[Path] = None) -> List[Tuple[str, Pattern[str]]]:
    """Load and pre-compile PII patterns from pii-stable.yml.

    Returns:
        List of (label_name, compiled_regex_pattern) tuples.
    """
    path = source_path or (SOURCES_DIR / "pii-stable.yml")
    if not path.exists():
        logger.debug(f"PII pattern source file not found at {path}")
        return []

    compiled_patterns: List[Tuple[str, Pattern[str]]] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_patterns = data.get("patterns", []) if isinstance(data, dict) else []
        for item in raw_patterns:
            p_dict = item.get("pattern", {}) if isinstance(item, dict) else {}
            name = str(p_dict.get("name", "PII Pattern")).strip()
            regex_str = p_dict.get("regex")

            if not regex_str or name.lower() in FILTERED_GENERIC_PATTERNS:
                continue

            try:
                # Compile regex with case-insensitivity
                compiled = re.compile(regex_str, re.IGNORECASE)
                compiled_patterns.append((f"PII: {name}", compiled))
            except re.error as err:
                logger.debug(f"Skipping invalid regex in {name}: {err}")

        logger.info(f"Loaded {len(compiled_patterns)} pre-compiled PII patterns from {path.name}")
    except Exception as err:
        logger.warning(f"Failed to load PII patterns from {path}: {err}")

    return compiled_patterns


@functools.lru_cache(maxsize=1)
def load_yaml_secret_rules(source_path: Optional[Path] = None) -> List[Tuple[str, Pattern[str]]]:
    """Load and pre-compile cloud credential and secret patterns from rules-stable.yml.

    Returns:
        List of (label_name, compiled_regex_pattern) tuples.
    """
    path = source_path or (SOURCES_DIR / "rules-stable.yml")
    if not path.exists():
        logger.debug(f"Secret rules source file not found at {path}")
        return []

    compiled_patterns: List[Tuple[str, Pattern[str]]] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_patterns = data.get("patterns", []) if isinstance(data, dict) else []
        for item in raw_patterns:
            p_dict = item.get("pattern", {}) if isinstance(item, dict) else {}
            name = str(p_dict.get("name", "Secret Rule")).strip()
            regex_str = p_dict.get("regex")
            confidence = str(p_dict.get("confidence", "high")).lower()

            # Focus on high/medium confidence rules to avoid false alarms
            if not regex_str or confidence not in ("high", "medium"):
                continue

            try:
                compiled = re.compile(regex_str, re.IGNORECASE)
                compiled_patterns.append((f"Secret: {name}", compiled))
            except re.error as err:
                logger.debug(f"Skipping invalid secret regex in {name}: {err}")

        logger.info(f"Loaded {len(compiled_patterns)} pre-compiled Secret rules from {path.name}")
    except Exception as err:
        logger.warning(f"Failed to load secret rules from {path}: {err}")

    return compiled_patterns


# Backward-compatibility alias
load_yaml_pii_rules = load_yaml_pii_patterns

