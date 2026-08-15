"""CSV data loaders for JailbreakBench datasets."""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Union, Any

logger = logging.getLogger("scanner.datasets")

BEHAVIOR_REQUIRED_COLUMNS = ["Index", "Goal", "Target", "Behavior", "Category", "Source"]
JUDGE_COMPARISON_REQUIRED_COLUMNS = [
    "Index",
    "goal",
    "prompt",
    "target_response",
    "human1",
    "human2",
    "human3",
    "human_majority",
    "harmbench_cf",
    "gpt4_cf",
    "llamaguard2_cf",
    "llama3_cf",
]


def load_behaviors_csv(path: Union[str, Path]) -> List[Dict[str, str]]:
    """Load harmful or benign behaviors CSV file into a list of row dictionaries.

    Args:
        path: Path string or Path object to CSV file.

    Returns:
        List of row dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If required columns are missing.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Behaviors CSV file not found: {filepath}")

    logger.info(f"Loading behaviors CSV from {filepath}")
    rows: List[Dict[str, str]] = []
    with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for col in BEHAVIOR_REQUIRED_COLUMNS:
            if col not in fieldnames:
                raise ValueError(f"Behaviors CSV '{filepath}' missing required column: '{col}'")

        for row in reader:
            rows.append(dict(row))

    logger.info(f"Loaded {len(rows)} behavior rows from {filepath}")
    return rows


def load_judge_comparison_csv(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load judge comparison CSV file and parse human_majority label into boolean.

    Args:
        path: Path string or Path object to CSV file.

    Returns:
        List of parsed row dictionaries where 'human_majority' is a bool.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If required columns are missing or human_majority has invalid values.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Judge comparison CSV file not found: {filepath}")

    logger.info(f"Loading judge comparison CSV from {filepath}")
    parsed_rows: List[Dict[str, Any]] = []
    with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for col in JUDGE_COMPARISON_REQUIRED_COLUMNS:
            if col not in fieldnames:
                raise ValueError(f"Judge comparison CSV '{filepath}' missing required column: '{col}'")

        for idx, row in enumerate(reader, start=1):
            raw_val = str(row["human_majority"]).strip()
            if raw_val == "1":
                human_maj_bool = True
            elif raw_val == "0":
                human_maj_bool = False
            else:
                raise ValueError(
                    f"Invalid 'human_majority' value '{raw_val}' at row {idx} in '{filepath}'. Expected '1' or '0'."
                )

            row_dict: Dict[str, Any] = dict(row)
            row_dict["human_majority"] = human_maj_bool
            parsed_rows.append(row_dict)

    logger.info(f"Loaded {len(parsed_rows)} judge comparison rows from {filepath}")
    return parsed_rows
