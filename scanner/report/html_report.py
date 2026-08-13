"""Jinja2 HTML report renderer."""

from pathlib import Path
from typing import Union
from jinja2 import Environment, FileSystemLoader

from scanner.models import ScanResult


TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(result: ScanResult, output_path: Union[str, Path]) -> Path:
    """Render scan results into a HTML report file using Jinja2 template.

    Args:
        result: ScanResult model instance.
        output_path: Path string or Path object destination.

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
    html_content = template.render(result=result)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return path
