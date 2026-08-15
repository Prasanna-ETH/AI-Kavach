"""Typer CLI interface for LLM Security Scanner with single-turn and multi-turn adversarial attack capabilities."""

import asyncio
import logging
from pathlib import Path
from typing import List, Optional
import random
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.adapters.rest_adapter import RESTAdapter
from scanner.attacker.attacker_llm import AttackerLLM
from scanner.config import load_multiturn_payloads, load_payloads
from scanner.datasets.csv_loader import load_behaviors_csv, load_judge_comparison_csv
from scanner.datasets.csv_to_yaml import convert_behaviors_to_payloads, save_payloads_to_yaml
from scanner.engine import ScanEngine
from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.llm_judge import LLMJudge, check_ollama_available, FALLBACK_JUDGE_TYPE
from scanner.models import Finding, MultiTurnFinding, MultiTurnPayload, Payload
from scanner.report.eval_report import compute_eval_metrics, generate_eval_report
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
    logger.info(f"Configuration: concurrency={concurrency}, delay={delay}s, use_llm_judge={use_llm_judge}")

    console.print(
        Panel(
            f"[bold cyan]LLM Security Scanner (AsyncIO Engine)[/bold cyan]\n"
            f"Target: [yellow]{url}[/yellow] | Concurrency: [bold green]{concurrency}[/bold green]",
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
    )

    # Health check: verify Ollama is available when LLM judge is requested
    if use_llm_judge:
        available, msg = asyncio.run(check_ollama_available(ollama_url="http://localhost:11434/api/chat"))
        if not available:
            console.print(f"[bold red]LLM Judge Unavailable:[/bold red] {msg}")
            raise typer.Exit(code=1)
        console.print(f"[bold green]✓[/bold green] {msg}")

    console.print(f"Loaded [bold green]{len(payloads)}[/bold green] attack payloads. Starting async scan...\n")

    def progress_callback(index: int, total: int, payload: Payload, finding: Optional[Finding]) -> None:
        if finding is None:
            return

        if finding.error:
            status_str = "[bold yellow]ERROR[/bold yellow]"
        elif finding.vulnerable:
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
            }.get(finding.severity.upper(), "bold red")
            status_str = f"[{sev_color}]VULNERABLE ({finding.severity})[/{sev_color}]"
        else:
            status_str = "[bold green]PASSED[/bold green]"

        console.print(
            f"[{index}/{total}] [{payload.owasp_id}] [bold]{payload.id}[/bold] ({payload.category}) -> {status_str}"
        )

    result = asyncio.run(engine.run(payloads, progress_callback=progress_callback))

    # Save reports
    json_path = generate_json_report(result, output_dir / "report.json")
    html_path = generate_html_report(result, output_dir / "report.html")

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]SCAN SUMMARY[/bold cyan]")
    console.print("=" * 60)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target Endpoint", result.target_url)
    summary_table.add_row("Total Payloads Executed", str(result.total_payloads))
    summary_table.add_row(
        "Vulnerabilities Flagged",
        f"[bold red]{result.vulnerable_count}[/bold red]" if result.vulnerable_count > 0 else "[bold green]0[/bold green]",
    )
    summary_table.add_row("Critical Severity", str(result.severity_counts.get("CRITICAL", 0)))
    summary_table.add_row("High Severity", str(result.severity_counts.get("HIGH", 0)))
    summary_table.add_row("Medium Severity", str(result.severity_counts.get("MEDIUM", 0)))
    summary_table.add_row("Low Severity", str(result.severity_counts.get("LOW", 0)))
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


dataset_app = typer.Typer(
    name="dataset",
    help="Dataset ingestion and judge evaluation subcommands.",
    add_completion=False,
)
app.add_typer(dataset_app, name="dataset", help="Dataset ingestion and judge evaluation tools.")


@dataset_app.command(name="import-behaviors")
def import_behaviors(
    csv_path: Path = typer.Option(..., "--csv", help="Path to input harmful or benign behaviors CSV file"),
    output_path: Path = typer.Option(..., "--output", help="Path to output YAML payload pack file"),
    label: str = typer.Option(..., "--label", help="Behavior classification label: 'harmful' or 'benign'"),
    category: str = typer.Option("jailbreak", "--category", help="Vulnerability category name"),
    owasp_id: str = typer.Option("LLM01", "--owasp-id", help="OWASP Top 10 category code"),
) -> None:
    """Convert JailbreakBench harmful or benign behaviors CSV into a reusable YAML payload pack."""
    label_clean = label.strip().lower()
    if label_clean == "harmful":
        expected_vulnerable = True
    elif label_clean == "benign":
        expected_vulnerable = False
    else:
        console.print("[bold red]Invalid --label value.[/bold red] Must be either 'harmful' or 'benign'.")
        raise typer.Exit(code=1)

    try:
        rows = load_behaviors_csv(csv_path)
        payload_dicts = convert_behaviors_to_payloads(
            rows,
            category=category,
            owasp_id=owasp_id,
            expected_vulnerable=expected_vulnerable,
        )
        saved_yaml = save_payloads_to_yaml(payload_dicts, output_path)

        console.print(
            Panel(
                f"[bold green]Dataset Successfully Converted & Imported[/bold green]\n\n"
                f"Source CSV: [cyan]{csv_path}[/cyan]\n"
                f"Rows Converted: [bold white]{len(payload_dicts)}[/bold white]\n"
                f"Label / Expected Vulnerable: [yellow]{'harmful (True)' if expected_vulnerable else 'benign (False)'}[/yellow]\n"
                f"Saved Payload Pack: [bold yellow]{saved_yaml.resolve()}[/bold yellow]",
                title="Import Summary",
                border_style="green",
            )
        )
    except Exception as err:
        console.print(f"[bold red]Import failed:[/bold red] {err}")
        raise typer.Exit(code=1)


@dataset_app.command(name="scan-behaviors")
def scan_behaviors(
    url: str = typer.Option(..., "--url", "-u", help="Target API endpoint URL"),
    body_template: str = typer.Option(
        '{"prompt": "{{PROMPT}}"}',
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
        help="Custom HTTP headers",
    ),
    pack: str = typer.Option(
        ...,
        "--pack",
        "-p",
        help="Payload pack filename or path (e.g. 'jbb_harmful.yaml')",
    ),
    delay: float = typer.Option(
        0.0,
        "--delay",
        "-d",
        help="Delay in seconds between requests",
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
        help="Safety authorization gate.",
    ),
    use_llm_judge: bool = typer.Option(
        False,
        "--use-llm-judge",
        help="Enforce local LLM Judge for all payload evaluations",
    ),
    output_dir: Path = typer.Option(
        Path("scan_results"),
        "--output-dir",
        "-o",
        help="Directory to save scan report files",
    ),
) -> None:
    """Execute scan using a dataset-derived payload pack and report success/false-positive metrics."""
    if not i_have_permission:
        console.print(
            Panel(
                "[bold red]SAFETY GATE BLOCKED[/bold red]\n\n"
                "You must explicitly provide the [yellow]--i-have-permission[/yellow] flag to confirm authorization.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    log_file = output_dir / "scan.log"
    logger = setup_logging(log_file)
    logger.info(f"Dataset Scan Behaviors initialized against {url} with pack {pack}")

    pack_path = Path(pack)
    if pack_path.exists() and pack_path.is_file():
        payloads = load_payloads(pack_names=[pack_path.stem], custom_dir=pack_path.parent)
    else:
        payloads = load_payloads(pack_names=[pack])

    if not payloads:
        console.print(f"[yellow]No payloads loaded from pack: {pack}[/yellow]")
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
    )

    console.print(f"Loaded [bold green]{len(payloads)}[/bold green] dataset payloads from [cyan]{pack}[/cyan]. Running scan...\n")

    def progress_callback(index: int, total: int, payload: Payload, finding: Optional[Finding]) -> None:
        if finding is None:
            return
        status_str = "[bold red]VULNERABLE[/bold red]" if finding.vulnerable else "[bold green]PASSED[/bold green]"
        console.print(f"[{index}/{total}] [{payload.id}] -> {status_str}")

    result = asyncio.run(engine.run(payloads, progress_callback=progress_callback))

    json_path = generate_json_report(result, output_dir / "report.json")
    html_path = generate_html_report(result, output_dir / "report.html")

    total_sent = result.total_payloads
    vuln_count = result.vulnerable_count
    vuln_pct = (vuln_count / total_sent * 100.0) if total_sent > 0 else 0.0

    exp_vuln_list = [p.expected_vulnerable for p in payloads if p.expected_vulnerable is not None]
    has_expectations = len(exp_vuln_list) == len(payloads)

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]DATASET BEHAVIORS SCAN SUMMARY[/bold cyan]")
    console.print("=" * 60)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target Endpoint", result.target_url)
    summary_table.add_row("Payload Pack", str(pack))
    summary_table.add_row("Total Payloads Sent", str(total_sent))
    summary_table.add_row("Vulnerabilities Flagged", f"{vuln_count} ({vuln_pct:.1f}%)")

    if has_expectations:
        all_expected_true = all(exp_vuln_list)
        all_expected_false = not any(exp_vuln_list)

        if all_expected_true:
            summary_table.add_row("Jailbreak Success Rate", f"[bold red]{vuln_pct:.2f}%[/bold red]")
        elif all_expected_false:
            summary_table.add_row("False Positive Rate", f"[bold yellow]{vuln_pct:.2f}%[/bold yellow]")
        else:
            correct_count = sum(1 for f in result.findings if f.payload.expected_vulnerable == f.vulnerable)
            acc_pct = (correct_count / total_sent * 100.0) if total_sent > 0 else 0.0
            summary_table.add_row("Dataset Scan Accuracy", f"[bold green]{acc_pct:.2f}%[/bold green]")

    console.print(summary_table)
    console.print("\n[bold green]Reports & Logs saved to:[/bold green]")
    console.print(f"  - HTML Report: [yellow]{html_path.resolve()}[/yellow]")
    console.print(f"  - JSON Report: [yellow]{json_path.resolve()}[/yellow]")
    console.print(f"  - Structured Log: [yellow]{log_file.resolve()}[/yellow]\n")


@dataset_app.command(name="eval-judge")
def eval_judge(
    csv_path: Path = typer.Option(..., "--csv", help="Path to judge-comparison.csv dataset file"),
    sample_size: Optional[int] = typer.Option(None, "--sample-size", "-s", help="Random sample size for faster iteration"),
    ollama_url: str = typer.Option("http://localhost:11434/api/chat", "--ollama-url", help="Ollama API endpoint URL"),
    judge_model: str = typer.Option("qwen2.5:0.5b", "--judge-model", help="Ollama LLM judge model name"),
    timeout: float = typer.Option(30.0, "--timeout", help="Timeout in seconds per LLM judge request"),
    output_dir: Path = typer.Option(Path("scan_results"), "--output-dir", "-o", help="Directory to save report files"),
) -> None:
    """Evaluate heuristic and LLM judge accuracy offline against JailbreakBench judge-comparison.csv."""
    log_file = output_dir / "scan.log"
    logger = setup_logging(log_file)
    logger.info(f"Evaluating judge against comparison dataset: {csv_path}")

    try:
        rows = load_judge_comparison_csv(csv_path)
    except Exception as err:
        console.print(f"[bold red]Failed to load CSV:[/bold red] {err}")
        raise typer.Exit(code=1)

    if sample_size and sample_size < len(rows):
        rows = random.sample(rows, sample_size)
        console.print(f"Sampled [bold yellow]{len(rows)}[/bold yellow] rows for evaluation.")
    else:
        console.print(f"Evaluating full dataset of [bold white]{len(rows)}[/bold white] rows...")

    # Health check: verify Ollama is reachable and model is installed before running eval
    available, health_msg = asyncio.run(check_ollama_available(
        ollama_url=ollama_url, model=judge_model, timeout=timeout,
    ))
    if not available:
        console.print(f"[bold red]LLM Judge Unavailable:[/bold red] {health_msg}")
        console.print(
            "[yellow]Cannot run judge evaluation without a working LLM judge. "
            "Fix the issue above and retry.[/yellow]"
        )
        raise typer.Exit(code=1)
    console.print(f"[bold green]✓[/bold green] {health_msg}")

    heuristic_judge = HeuristicJudge()
    llm_judge = LLMJudge(ollama_url=ollama_url, model=judge_model, timeout=timeout)

    async def run_eval() -> List[dict]:
        results = []
        for idx, row in enumerate(rows, start=1):
            payload = Payload(
                id=f"JBB-EVAL-{row['Index']}",
                category="jailbreak",
                owasp_id="LLM01",
                prompt=str(row["prompt"]),
                severity="HIGH",
                requires_llm_judge=True,
            )
            response_text = str(row["target_response"])

            # 1. Heuristic judge check
            finding = await heuristic_judge.evaluate(payload, response_text)
            # 2. Fall through to LLM judge if heuristic did not flag vulnerable
            if not finding.vulnerable:
                finding = await llm_judge.evaluate(payload, response_text)

            results.append({
                "row": row,
                "finding": finding,
                "human_majority": row["human_majority"],
            })
            # Display fallback judge_type distinctly so LLM failures are impossible to miss
            jtype = finding.judge_type
            if FALLBACK_JUDGE_TYPE in jtype:
                jtype_display = f"[bold red]⚠ {jtype}[/bold red]"
            elif jtype == "llm":
                jtype_display = f"[bold cyan]{jtype}[/bold cyan]"
            else:
                jtype_display = jtype
            console.print(
                f"[{idx}/{len(rows)}] Index {row['Index']} | Pred: {finding.vulnerable} | "
                f"GroundTruth: {row['human_majority']} | Judge: {jtype_display}"
            )
        return results

    eval_results = asyncio.run(run_eval())
    metrics_data = compute_eval_metrics(eval_results)

    json_report_path = generate_eval_report(metrics_data, output_dir / "judge_eval_report.json")
    html_report_path = generate_html_report(result=None, output_path=output_dir / "report.html", eval_report_data=metrics_data)

    summary = metrics_data["summary"]
    benchmarks = metrics_data["benchmarks"]

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]JUDGE ACCURACY EVALUATION RESULTS[/bold cyan]")
    console.print("=" * 60)

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Total Evaluated Samples", str(summary["total_samples"]))
    summary_table.add_row("Accuracy", f"[bold green]{summary['accuracy'] * 100:.2f}%[/bold green]")
    summary_table.add_row("Precision", f"{summary['precision'] * 100:.2f}%")
    summary_table.add_row("Recall", f"{summary['recall'] * 100:.2f}%")
    summary_table.add_row("F1 Score", f"[bold cyan]{summary['f1_score']:.4f}[/bold cyan]")
    summary_table.add_row("True Positives (TP)", str(summary["true_positives"]))
    summary_table.add_row("False Positives (FP)", f"[bold red]{summary['false_positives']}[/bold red]")
    summary_table.add_row("True Negatives (TN)", str(summary["true_negatives"]))
    summary_table.add_row("False Negatives (FN)", f"[bold yellow]{summary['false_negatives']}[/bold yellow]")

    console.print(summary_table)

    if benchmarks:
        console.print("\n[bold cyan]Automated Judge Benchmark Comparisons (Agreement vs Human Majority):[/bold cyan]")
        bm_table = Table(show_header=True, header_style="bold yellow")
        bm_table.add_column("Benchmark Judge", style="cyan")
        bm_table.add_column("Agreement Accuracy", style="white")

        bm_table.add_row("LLM Sentinel Judge (Our Judge)", f"[bold green]{summary['accuracy'] * 100:.2f}%[/bold green]")
        for b_name, b_val in benchmarks.items():
            bm_table.add_row(b_name, f"{b_val['accuracy'] * 100:.2f}% ({b_val['correct']}/{b_val['total']})")
        console.print(bm_table)

    # Print False Positives
    fps = metrics_data["false_positives"]
    if fps:
        console.print(f"\n[bold red]FALSE POSITIVES ({len(fps)} items):[/bold red]")
        for fp_item in fps:
            goal_trunc = str(fp_item['goal'])[:150]
            resp_trunc = str(fp_item['target_response'])[:150]
            jt = fp_item['judge_type']
            jt_str = f"[bold red]⚠ {jt}[/bold red]" if "fallback" in jt else jt
            console.print(
                f"[yellow]Row {fp_item['index']}[/yellow] - Judge: {jt_str}\n"
                f"  Goal: [white]{goal_trunc}[/white]\n"
                f"  Target Response: [dim]{resp_trunc}[/dim]\n"
            )

    # Print False Negatives
    fns = metrics_data["false_negatives"]
    if fns:
        console.print(f"\n[bold yellow]FALSE NEGATIVES ({len(fns)} items):[/bold yellow]")
        for fn_item in fns:
            goal_trunc = str(fn_item['goal'])[:150]
            resp_trunc = str(fn_item['target_response'])[:150]
            jt = fn_item['judge_type']
            jt_str = f"[bold red]⚠ {jt}[/bold red]" if "fallback" in jt else jt
            console.print(
                f"[yellow]Row {fn_item['index']}[/yellow] - Judge: {jt_str}\n"
                f"  Goal: [white]{goal_trunc}[/white]\n"
                f"  Target Response: [dim]{resp_trunc}[/dim]\n"
            )

    console.print("\n[bold green]Evaluation Reports saved to:[/bold green]")
    console.print(f"  - JSON Report: [yellow]{json_report_path.resolve()}[/yellow]")
    console.print(f"  - HTML Report: [yellow]{html_report_path.resolve()}[/yellow]\n")


if __name__ == "__main__":
    app()
