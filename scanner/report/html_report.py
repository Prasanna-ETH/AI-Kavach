"""Jinja2 HTML report renderer for single-turn and multi-turn scan results."""

from pathlib import Path
from typing import List, Optional, Union
from jinja2 import Environment, FileSystemLoader

from scanner.models import MultiTurnFinding, ScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(
    result: Optional[ScanResult],
    output_path: Union[str, Path],
    multiturn_findings: Optional[List[MultiTurnFinding]] = None,
    target_url: str = "http://localhost:5000/api/chat",
) -> Path:
    """Render scan results into a HTML report file using Jinja2 template.

    Args:
        result: Single-turn ScanResult model instance (optional if multi-turn).
        output_path: Path string or Path object destination.
        multiturn_findings: List of MultiTurnFinding objects (optional).
        target_url: Target URL string fallback.

    Returns:
        Path object pointing to generated HTML file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    html_content = template.render(
        result=result,
        multiturn_findings=multiturn_findings,
        target_url=target_url if not result else result.target_url,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return path
