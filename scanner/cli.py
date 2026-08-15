"""Typer CLI interface for LLM Security Scanner with single-turn and multi-turn adversarial attack capabilities."""

import asyncio
import logging
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.adapters.rest_adapter import RESTAdapter
from scanner.attacker.attacker_llm import AttackerLLM
from scanner.config import load_multiturn_payloads, load_payloads
from scanner.engine import ScanEngine
from scanner.models import Finding, MultiTurnFinding, MultiTurnPayload, Payload
from scanner.report.html_report import generate_html_report
from scanner.report.json_report import generate_json_report, generate_multiturn_json_report

app = typer.Typer(
    name="scanner",
    help="CLI security scanner for LLM API endpoints mapped to OWASP Top 10 for LLM Applications.",
    add_completion=False,
)

console = Console()


def setup_logging(log_file_path: Path) -> logging.Logger:
    """Configure structured Python logging writing to scan.log file and console debug."""
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO)

    root_logger.handlers = [h for h in root_logger.handlers if not isinstance(h, logging.FileHandler)]
    root_logger.addHandler(file_handler)

    return logging.getLogger("scanner.cli")


def parse_headers(header_args: Optional[List[str]]) -> dict[str, str]:
    """Parse list of header strings like 'Authorization: Bearer xyz' into dict."""
    headers = {"Content-Type": "application/json"}
    if not header_args:
        return headers

    for h in header_args:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()
        elif " " in h:
            key, val = h.split(" ", 1)
            headers[key.strip()] = val.strip()
        else:
            headers["Authorization"] = h.strip()
    return headers


@app.callback()
def main() -> None:
    """LLM Security Scanner CLI."""
    pass


@app.command(name="scan")
def scan(
    url: str = typer.Option(..., "--url", "-u", help="Target API endpoint URL"),
    body_template: str = typer.Option(
        ...,
        "--body-template",
        "-b",
        help="JSON body string template with {{PROMPT}} placeholder",
    ),
    response_field: str = typer.Option(
        "message.content",
        "--response-field",
        "-r",
        help="Dotted path key to extract model response text",
    ),
    auth_header: Optional[List[str]] = typer.Option(
        None,
        "--auth-header",
        "-a",
        help="Custom HTTP headers (e.g. 'Authorization: Bearer key')",
    ),
    packs: Optional[str] = typer.Option(
        None,
        "--packs",
        "-p",
        help="Comma-separated payload packs to execute (e.g., 'prompt_injection,jailbreak')",
    ),
    delay: float = typer.Option(
        0.0,
        "--delay",
        "-d",
        help="Delay in seconds between requests per worker",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Maximum simultaneous async HTTP requests",
    ),
    i_have_permission: bool = typer.Option(
        False,
        "--i-have-permission",
        help="Safety authorization gate. MUST be explicitly provided to execute scans.",
    ),
    use_llm_judge: bool = typer.Option(
        False,
        "--use-llm-judge",
        help="Enforce local LLM Judge for all payload evaluations",
    ),
    judge_model: str = typer.Option(
        "qwen2.5:3b",
        "--judge-model",
        help="Local Ollama model name used for LLM Judge evaluations",
    ),
    output_dir: Path = typer.Option(
        Path("scan_results"),
        "--output-dir",
        "-o",
        help="Directory to save report.html, report.json, and scan.log",
    ),
) -> None:
    """Execute single-turn security scan asynchronously against target LLM API endpoint."""
    if not i_have_permission:
        console.print(
            Panel(
                "[bold red]SAFETY GATE BLOCKED[/bold red]\n\n"
                "You must explicitly provide the [yellow]--i-have-permission[/yellow] flag to confirm you have "
                "authorization to perform security scans against the target endpoint.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    log_file = output_dir / "scan.log"
    logger = setup_logging(log_file)

    logger.info(f"LLM Security Scanner initialized against target: {url}")
    logger.info(f"Configuration: concurrency={concurrency}, delay={delay}s, use_llm_judge={use_llm_judge}, judge_model={judge_model}")

    console.print(
        Panel(
            f"[bold cyan]LLM Security Scanner (AsyncIO Engine)[/bold cyan]\n"
            f"Target: [yellow]{url}[/yellow] | Concurrency: [bold green]{concurrency}[/bold green] | Judge: [bold magenta]{judge_model}[/bold magenta]",
            border_style="cyan",
        )
    )

    pack_list = [p.strip() for p in packs.split(",")] if packs else None

    try:
        payloads = load_payloads(pack_names=pack_list)
    except Exception as err:
        logger.error(f"Failed to load payload packs: {err}")
        console.print(f"[bold red]Failed to load payload packs:[/bold red] {err}")
        raise typer.Exit(code=1)

    if not payloads:
        console.print("[yellow]No payloads found matching specified criteria.[/yellow]")
        raise typer.Exit(code=0)

    headers = parse_headers(auth_header)
    adapter = RESTAdapter(
        url=url,
        body_template=body_template,
        response_field=response_field,
        headers=headers,
    )

    engine = ScanEngine(
        adapter=adapter,
        delay=delay,
        concurrency=concurrency,
        use_llm_judge=use_llm_judge,
        judge_model=judge_model,
    )

    console.print(f"Loaded [bold green]{len(payloads)}[/bold green] attack payloads. Starting async scan...\n")

    def progress_callback(index: int, total: int, payload: Payload, finding: Optional[Finding]) -> None:
        if finding is None:
            return

        if finding.error:
            status_str = "[bold yellow]ERROR[/bold yellow]"
        else:
            score = getattr(finding, "likert_score", 4 if finding.vulnerable else 0)
            score_badge = {
                0: "[bold green][Score 0/4 SAFE][/bold green]",
                1: "[bold cyan][Score 1/4 BENIGN][/bold cyan]",
                2: "[bold yellow][Score 2/4 WARNING][/bold yellow]",
                3: "[bold magenta][Score 3/4 HIGH][/bold magenta]",
                4: "[bold red][Score 4/4 CRITICAL][/bold red]",
            }.get(score, "[bold red][VULNERABLE][/bold red]")

            if finding.vulnerable:
                status_str = f"{score_badge} [bold red]VULNERABLE ({finding.severity})[/bold red]"
            else:
                status_str = f"{score_badge} [bold green]PASSED[/bold green]"

        console.print(
            f"[{index}/{total}] [{payload.owasp_id}] [bold]{payload.id}[/bold] ({payload.category}) -> {status_str}"
        )

    result = asyncio.run(engine.run(payloads, progress_callback=progress_callback))

    # Save reports
    json_path = generate_json_report(result, output_dir / "report.json")
    html_path = generate_html_report(result, output_dir / "report.html")

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]SCAN SUMMARY & POSTURE SCORE[/bold cyan]")
    console.print("=" * 60)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    grade_color = {
        "A": "bold green",
        "B": "green",
        "C": "yellow",
        "D": "orange3",
        "F": "bold red",
    }.get(result.grade, "white")

    summary_table.add_row("Target Endpoint", result.target_url)
    summary_table.add_row(
        "Security Posture Score",
        f"[{grade_color}]{result.posture_score:.1f} / 100.0 (Grade {result.grade})[/{grade_color}]",
    )
    summary_table.add_row("Total Payloads Executed", str(result.total_payloads))
    summary_table.add_row(
        "Vulnerabilities Flagged",
        f"[bold red]{result.vulnerable_count}[/bold red]" if result.vulnerable_count > 0 else "[bold green]0[/bold green]",
    )
    summary_table.add_row("Likert 0 (Safe / Refusal)", f"[green]{result.likert_distribution.get(0, 0)}[/green]")
    summary_table.add_row("Likert 1 (Benign Context)", f"[cyan]{result.likert_distribution.get(1, 0)}[/cyan]")
    summary_table.add_row("Likert 2 (Boundary Slip)", f"[yellow]{result.likert_distribution.get(2, 0)}[/yellow]")
    summary_table.add_row("Likert 3 (Substantial Harm)", f"[magenta]{result.likert_distribution.get(3, 0)}[/magenta]")
    summary_table.add_row("Likert 4 (Critical Exploit)", f"[bold red]{result.likert_distribution.get(4, 0)}[/bold red]")
    summary_table.add_row("Circuit Broken", "Yes" if result.circuit_broken else "No")
    summary_table.add_row("Scan Duration", f"{result.duration_seconds:.2f} seconds")

    console.print(summary_table)
    console.print("\n[bold green]Reports & Logs saved to:[/bold green]")
    console.print(f"  - HTML Report: [yellow]{html_path.resolve()}[/yellow]")
    console.print(f"  - JSON Report: [yellow]{json_path.resolve()}[/yellow]")
    console.print(f"  - Structured Log: [yellow]{log_file.resolve()}[/yellow]\n")


@app.command(name="scan-multiturn")
def scan_multiturn(
    url: str = typer.Option(..., "--url", "-u", help="Target API endpoint URL"),
    body_template: str = typer.Option(
        ...,
        "--body-template",
        "-b",
        help="JSON body string template with {{PROMPT}} placeholder",
    ),
    response_field: str = typer.Option(
        "message.content",
        "--response-field",
        "-r",
        help="Dotted path key to extract model response text",
    ),
    attacker_model: str = typer.Option(
        "qwen2.5:0.5b",
        "--attacker-model",
        help="Ollama model for the adversarial Attacker LLM driver",
    ),
    judge_model: str = typer.Option(
        "qwen2.5:0.5b",
        "--judge-model",
        help="Ollama model for the Multi-Turn Judge evaluator",
    ),
    max_turns: int = typer.Option(
        4,
        "--max-turns",
        "-m",
        help="Maximum turns per conversation (hard capped at 8 max)",
    ),
    auth_header: Optional[List[str]] = typer.Option(
        None,
        "--auth-header",
        "-a",
        help="Custom HTTP headers",
    ),
    packs: Optional[str] = typer.Option(
        None,
        "--packs",
        "-p",
        help="Comma-separated multi-turn payload pack names",
    ),
    delay: float = typer.Option(
        0.5,
        "--delay",
        "-d",
        help="Delay in seconds between request turns",
    ),
    i_have_permission: bool = typer.Option(
        False,
        "--i-have-permission",
        help="Safety authorization gate. MUST be explicitly provided to execute scans.",
    ),
    output_dir: Path = typer.Option(
        Path("scan_results"),
        "--output-dir",
        "-o",
        help="Directory to save multiturn_report.json, report.html, and scan.log",
    ),
) -> None:
    """Execute multi-turn adversarial attack scan against target LLM API endpoint."""
    if not i_have_permission:
        console.print(
            Panel(
                "[bold red]SAFETY GATE BLOCKED[/bold red]\n\n"
                "You must explicitly provide the [yellow]--i-have-permission[/yellow] flag to confirm you have "
                "authorization to perform security scans against the target endpoint.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    log_file = output_dir / "scan.log"
    logger = setup_logging(log_file)

    logger.info(f"Multi-Turn Security Scanner initialized against target: {url}")
    logger.info(f"Attacker Model: {attacker_model} | Judge Model: {judge_model} | Max Turns: {max_turns}")

    console.print(
        Panel(
            f"[bold cyan]Multi-Turn Adversarial Attack Scanner[/bold cyan]\n"
            f"Target: [yellow]{url}[/yellow] | Attacker Model: [bold green]{attacker_model}[/bold green]",
            border_style="cyan",
        )
    )

    pack_list = [p.strip() for p in packs.split(",")] if packs else None

    try:
        mt_payloads = load_multiturn_payloads(pack_names=pack_list)
        for p in mt_payloads:
            p.max_turns = min(max_turns, 8)
    except Exception as err:
        logger.error(f"Failed to load multi-turn payload packs: {err}")
        console.print(f"[bold red]Failed to load multi-turn payload packs:[/bold red] {err}")
        raise typer.Exit(code=1)

    if not mt_payloads:
        console.print("[yellow]No multi-turn payloads found matching criteria.[/yellow]")
        raise typer.Exit(code=0)

    headers = parse_headers(auth_header)
    adapter = RESTAdapter(
        url=url,
        body_template=body_template,
        response_field=response_field,
        headers=headers,
    )

    attacker = AttackerLLM(model=attacker_model)
    engine = ScanEngine(adapter=adapter, delay=delay)

    console.print(
        f"Loaded [bold green]{len(mt_payloads)}[/bold green] multi-turn attack scenarios. Executing conversation loops...\n"
    )

    def progress_callback(
        p_idx: int,
        p_total: int,
        payload: MultiTurnPayload,
        turn: int,
        t_max: int,
        status_msg: str,
        finding: Optional[MultiTurnFinding],
    ) -> None:
        if finding is None:
            console.print(f"[{payload.owasp_id}] [bold]{payload.id}[/bold] Turn {turn}/{t_max}: {status_msg}")
        else:
            if finding.vulnerable:
                status_str = f"[bold red]VULNERABLE (Exploited at Turn {finding.succeeded_at_turn})[/bold red]"
            else:
                status_str = "[bold green]PASSED (Target Remained Safe)[/bold green]"
            console.print(f"[{payload.owasp_id}] [bold]{payload.id}[/bold] Final Result -> {status_str}\n")

    findings = asyncio.run(engine.run_multiturn_scan(attacker, mt_payloads, progress_callback=progress_callback))

    json_path = generate_multiturn_json_report(findings, output_dir / "multiturn_report.json")
    html_path = generate_html_report(result=None, output_path=output_dir / "report.html", multiturn_findings=findings, target_url=url)

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]MULTI-TURN SCAN SUMMARY[/bold cyan]")
    console.print("=" * 60)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    vuln_count = sum(1 for f in findings if f.vulnerable)

    summary_table.add_row("Target Endpoint", url)
    summary_table.add_row("Attacker Model", attacker_model)
    summary_table.add_row("Total Scenarios Tested", str(len(findings)))
    summary_table.add_row(
        "Vulnerabilities Flagged",
        f"[bold red]{vuln_count}[/bold red]" if vuln_count > 0 else "[bold green]0[/bold green]",
    )

    console.print(summary_table)
    console.print("\n[bold green]Reports & Logs saved to:[/bold green]")
    console.print(f"  - HTML Report: [yellow]{html_path.resolve()}[/yellow]")
    console.print(f"  - JSON Report: [yellow]{json_path.resolve()}[/yellow]")
    console.print(f"  - Structured Log: [yellow]{log_file.resolve()}[/yellow]\n")


if __name__ == "__main__":
    app()
