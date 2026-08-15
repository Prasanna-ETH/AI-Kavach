"""Report generation package for HTML and JSON scan reports."""

from scanner.report.json_report import generate_json_report
from scanner.report.html_report import generate_html_report

__all__ = ["generate_json_report", "generate_html_report"]
