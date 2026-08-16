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

from datetime import datetime, timezone
import time

from scanner.adapters.rest_adapter import RESTAdapter
from scanner.adapters.playwright_adapter import PlaywrightAdapter
from scanner.attacker.attacker_llm import AttackerLLM
from scanner.config import load_multiturn_payloads, load_payloads
from scanner.converters.registry import get_converter
from scanner.datasets.csv_loader import load_behaviors_csv, load_judge_comparison_csv
from scanner.datasets.csv_to_yaml import convert_behaviors_to_payloads, save_payloads_to_yaml
from scanner.engine import ScanEngine, run_scan_with_converters
from scanner.judge.heuristics import HeuristicJudge
from scanner.judge.likert_judge import LikertJudge
from scanner.judge.llm_judge import LLMJudge, check_ollama_available, FALLBACK_JUDGE_TYPE
from scanner.models import Finding, MultiTurnFinding, MultiTurnPayload, Payload, ScanResult
from scanner.report.eval_report import compute_eval_metrics, generate_eval_report
from scanner.report.html_report import generate_html_report
from scanner.report.json_report import generate_json_report, generate_multiturn_json_report
from scanner.scoring import calculate_likert_distribution, calculate_posture_score

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
    body_template: Optional[str] = typer.Option(
        None,
        "--body-template",
        "-b",
        help="JSON body string template with {{PROMPT}} placeholder (required for REST mode)",
    ),
    response_field: str = typer.Option(
        "message.content",
        "--response-field",
        "-r",
        help="Dotted path key to extract model response text (for REST mode)",
    ),
    browser: bool = typer.Option(
        False,
        "--browser",
        "-B",
        help="Use Playwright browser automation to scan web forms and browser chat UIs directly",
    ),
    input_selector: str = typer.Option(
        "textarea, input[name='message'], input[name='prompt'], input[type='text']",
        "--input-selector",
        help="CSS selector for chat input field (used with --browser)",
    ),
    submit_selector: str = typer.Option(
        "button[type='submit'], button#send, button.send, input[type='submit']",
        "--submit-selector",
        help="CSS selector for form submit/send button (used with --browser)",
    ),
    response_selector: str = typer.Option(
        ".message.assistant, .bot-message, .chat-response, .ai-response, div[data-role='assistant'], #chat-response",
        "--response-selector",
        help="CSS selector for assistant response container (used with --browser)",
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
    converters: Optional[str] = typer.Option(
        None,
        "--converters",
        help="Comma-separated payload converters to apply (e.g. 'base64,leetspeak,rot13,translation_zulu')",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-l",
        help="Limit execution to the first N payloads (e.g. --limit 5)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Display prompt, target response, and judge reasoning in console output",
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
    logger.info(f"Configuration: concurrency={concurrency}, delay={delay}s, use_llm_judge={use_llm_judge}, judge_model={judge_model}, converters={converters}, limit={limit}, verbose={verbose}")

    console.print(
        Panel(
            f"[bold cyan]LLM Security Scanner (AsyncIO Engine)[/bold cyan]\n"
            f"Target: [yellow]{url}[/yellow] | Concurrency: [bold green]{concurrency}[/bold green] | Judge Model: [bold magenta]{judge_model}[/bold magenta]",
            border_style="cyan",
        )
    )

    converter_instances = []
    if converters:
        raw_names = [c.strip() for c in converters.split(",") if c.strip()]
        for cname in raw_names:
            try:
                converter_instances.append(get_converter(cname))
            except ValueError as err:
                logger.error(f"Invalid converter specified: {err}")
                console.print(f"[bold red]Converter Error:[/bold red] {err}")
                raise typer.Exit(code=1)

    pack_list = [p.strip() for p in packs.split(",")] if packs else None

    try:
        payloads = load_payloads(pack_names=pack_list)
        if limit and limit > 0:
            payloads = payloads[:limit]
    except Exception as err:
        logger.error(f"Failed to load payload packs: {err}")
        console.print(f"[bold red]Failed to load payload packs:[/bold red] {err}")
        raise typer.Exit(code=1)

    if not payloads:
        console.print("[yellow]No payloads found matching specified criteria.[/yellow]")
        raise typer.Exit(code=0)

    if browser:
        console.print(f"[bold cyan]Launching Playwright browser adapter for URL:[/bold cyan] {url}")
        adapter = PlaywrightAdapter(
            url=url,
            input_selector=input_selector,
            submit_selector=submit_selector,
            response_selector=response_selector,
        )
    else:
        if not body_template:
            body_template = '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
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

    console.print(f"Loaded [bold green]{len(payloads)}[/bold green] attack payloads. Starting scan...\n")

    if converter_instances:
        plain_vulnerable_map: dict[str, bool] = {}

        def conv_progress_callback(
            idx: int,
            total: int,
            payload: Payload,
            variant_name: Optional[str],
            finding: Finding,
        ) -> None:
            v_name = variant_name if variant_name else "plain"
            if finding.error:
                res_str = f"[bold red]ERROR: {finding.error}[/bold red]"
            else:
                score = getattr(finding, "likert_score", 4 if finding.vulnerable else 0)
                score_badge = {
                    0: "[bold green][Score 0/4 SAFE][/bold green]",
                    1: "[bold cyan][Score 1/4 BENIGN][/bold cyan]",
                    2: "[bold yellow][Score 2/4 WARNING][/bold yellow]",
                    3: "[bold magenta][Score 3/4 HIGH][/bold magenta]",
                    4: "[bold red][Score 4/4 CRITICAL][/bold red]",
                }.get(score, "[bold red][VULNERABLE][/bold red]")

                if variant_name is None:
                    plain_vulnerable_map[payload.id] = finding.vulnerable
                    res_str = f"{score_badge} [bold red]VULNERABLE[/bold red]" if finding.vulnerable else f"{score_badge} [bold green]SAFE[/bold green]"
                else:
                    plain_vuln = plain_vulnerable_map.get(payload.id, False)
                    if finding.vulnerable != plain_vuln:
                        if finding.vulnerable:
                            res_str = f"{score_badge} [bold red blink]VULNERABLE  <-- bypass detected![/bold red blink]"
                        else:
                            res_str = f"{score_badge} [bold yellow]SAFE  (plain was vulnerable)[/bold yellow]"
                    else:
                        res_str = f"{score_badge} [bold red]VULNERABLE[/bold red]" if finding.vulnerable else f"{score_badge} [bold green]SAFE[/bold green]"

            console.print(f"[{payload.id}] {v_name}: {res_str}")

            if verbose:
                console.print(f"    [dim cyan]Prompt:[/dim cyan] {finding.payload.prompt[:120]!r}")
                console.print(f"    [dim magenta]Response:[/dim magenta] {finding.response_text[:120]!r}")
                console.print(f"    [dim yellow]Judge ({finding.judge_type}):[/dim yellow] {finding.reasoning}")

        start_t = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()
        findings = asyncio.run(
            run_scan_with_converters(
                adapter=adapter,
                payloads=payloads,
                converters=converter_instances,
                delay=delay,
                use_llm_judge=use_llm_judge,
                judge_model=judge_model,
                progress_callback=conv_progress_callback,
            )
        )
        end_t = time.time()
        end_iso = datetime.now(timezone.utc).isoformat()

        dist = calculate_likert_distribution(findings)
        posture_score, grade, category_scores = calculate_posture_score(findings)

        result = ScanResult(
            target_url=url,
            start_time=start_iso,
            end_time=end_iso,
            total_payloads=len(findings),
            findings=findings,
            circuit_broken=False,
            duration_seconds=end_t - start_t,
            likert_distribution=dist,
            posture_score=posture_score,
            grade=grade,
            category_scores=category_scores,
        )
    else:
        def progress_callback(index: int, total: int, payload: Payload, finding: Optional[Finding]) -> None:
            if finding is None:
                return

            if finding.error:
                status_str = f"[bold red]ERROR: {finding.error}[/bold red]"
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

            if verbose:
                console.print(f"    [dim cyan]Prompt:[/dim cyan] {payload.prompt[:120]!r}")
                console.print(f"    [dim magenta]Response:[/dim magenta] {finding.response_text[:120]!r}")
                console.print(f"    [dim yellow]Judge ({finding.judge_type}):[/dim yellow] {finding.reasoning}")

        result = asyncio.run(engine.run(payloads, progress_callback=progress_callback))

    # Save reports
    json_path = generate_json_report(result, output_dir / "report.json")
    html_path = generate_html_report(result, output_dir / "report.html")

    # 1. Print Detailed Findings Table in Terminal
    console.print("\n" + "=" * 80)
    console.print("[bold cyan]SCAN FINDINGS DETAILS[/bold cyan]")
    console.print("=" * 80)

    findings_table = Table(show_header=True, header_style="bold magenta")
    findings_table.add_column("ID", style="cyan", no_wrap=True)
    findings_table.add_column("OWASP", style="blue", no_wrap=True)
    findings_table.add_column("Category", style="white")
    findings_table.add_column("Likert", justify="center")
    findings_table.add_column("Status", justify="center")
    findings_table.add_column("Judge", style="yellow")
    findings_table.add_column("Reasoning / Response Preview", style="dim")

    for f in result.findings:
        if f.error:
            status_cell = "[bold red]ERROR[/bold red]"
            score_cell = "[dim]-[/dim]"
            reason_preview = f.error[:80]
        elif f.vulnerable:
            status_cell = f"[bold red]VULNERABLE ({f.severity})[/bold red]"
            score_cell = f"[bold red]{f.likert_score}/4[/bold red]"
            reason_preview = f.reasoning[:80] if f.reasoning else f.response_text[:80]
        else:
            status_cell = "[bold green]PASSED[/bold green]"
            score_cell = f"[bold green]{f.likert_score}/4[/bold green]"
            reason_preview = f.reasoning[:80] if f.reasoning else f.response_text[:80]

        findings_table.add_row(
            f.payload.id,
            f.payload.owasp_id,
            f.payload.category,
            score_cell,
            status_cell,
            f.judge_type,
            reason_preview,
        )

    console.print(findings_table)

    # 2. Print Summary & Posture Table
    console.print("\n" + "=" * 80)
    console.print("[bold cyan]SECURITY POSTURE SCORE & SCAN SUMMARY[/bold cyan]")
    console.print("=" * 80)

    if result.circuit_broken:
        console.print(
            Panel(
                "[bold red]⚠️ CIRCUIT BREAKER TRIGGERED[/bold red]\n"
                "The target endpoint failed consecutive HTTP requests. The scan was aborted early to prevent overwhelming the target.",
                border_style="red",
            )
        )

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
    summary_table.add_row("Circuit Broken", "[bold red]Yes[/bold red]" if result.circuit_broken else "[bold green]No[/bold green]")
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
    engine = ScanEngine(adapter=adapter, delay=delay, judge_model=judge_model)

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
        '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
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
    judge_model: str = typer.Option(
        "qwen2.5:3b",
        "--judge-model",
        help="Local Ollama model name used for LLM Judge evaluations",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-l",
        help="Limit execution to the first N payloads (e.g. --limit 5)",
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

    if limit and limit > 0:
        payloads = payloads[:limit]

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
        judge_model=judge_model,
    )

    console.print(f"Loaded [bold green]{len(payloads)}[/bold green] dataset payloads from [cyan]{pack}[/cyan]. Running scan...\n")

    def progress_callback(index: int, total: int, payload: Payload, finding: Optional[Finding]) -> None:
        if finding is None:
            return
        score = getattr(finding, "likert_score", 4 if finding.vulnerable else 0)
        score_badge = {
            0: "[bold green][Score 0/4 SAFE][/bold green]",
            1: "[bold cyan][Score 1/4 BENIGN][/bold cyan]",
            2: "[bold yellow][Score 2/4 WARNING][/bold yellow]",
            3: "[bold magenta][Score 3/4 HIGH][/bold magenta]",
            4: "[bold red][Score 4/4 CRITICAL][/bold red]",
        }.get(score, "[bold red][VULNERABLE][/bold red]")
        status_str = f"{score_badge} [bold red]VULNERABLE[/bold red]" if finding.vulnerable else f"{score_badge} [bold green]PASSED[/bold green]"
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
    summary_table.add_row("Security Posture Score", f"{result.posture_score:.1f} / 100.0 (Grade {result.grade})")
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
    judge_model: str = typer.Option("qwen2.5:3b", "--judge-model", help="Ollama LLM judge model name"),
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
    console.print(f"[bold green][OK][/bold green] {health_msg}")

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
                jtype_display = f"[bold red]! {jtype}[/bold red]"
            elif jtype == "llm":
                jtype_display = f"[bold cyan]{jtype}[/bold cyan]"
            else:
                jtype_display = jtype
            console.print(
                f"[{idx}/{len(rows)}] Row {row['Index']} -> "
                f"Predicted: {'[bold red]VULN[/bold red]' if finding.vulnerable else '[bold green]SAFE[/bold green]'} | "
                f"Human: {'[bold red]VULN[/bold red]' if row['human_majority'] else '[bold green]SAFE[/bold green]'} | "
                f"Judge: {jtype_display}"
            )
        return results

    eval_results = asyncio.run(run_eval())
    eval_report_data = compute_eval_metrics(eval_results, model_name=judge_model)

    json_path = output_dir / "judge_eval_report.json"
    generate_eval_report(eval_report_data, json_path)
    html_path = generate_html_report(result=None, output_path=output_dir / "report.html", eval_report_data=eval_report_data)

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]JUDGE ACCURACY EVALUATION SUMMARY[/bold cyan]")
    console.print("=" * 60)

    s = eval_report_data["summary"]
    metrics_table = Table(show_header=True, header_style="bold magenta")
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Value", style="white")

    metrics_table.add_row("Judge Model", judge_model)
    metrics_table.add_row("Total Samples", str(s["total_samples"]))
    metrics_table.add_row("Accuracy", f"[bold green]{s['accuracy'] * 100:.1f}%[/bold green]")
    metrics_table.add_row("Precision", f"{s['precision'] * 100:.1f}%")
    metrics_table.add_row("Recall", f"{s['recall'] * 100:.1f}%")
    metrics_table.add_row("F1 Score", f"[bold cyan]{s['f1_score']:.3f}[/bold cyan]")
    metrics_table.add_row("True Positives (TP)", str(s["true_positives"]))
    metrics_table.add_row("False Positives (FP)", f"[bold red]{s['false_positives']}[/bold red]" if s["false_positives"] > 0 else "0")
    metrics_table.add_row("True Negatives (TN)", str(s["true_negatives"]))
    metrics_table.add_row("False Negatives (FN)", f"[bold red]{s['false_negatives']}[/bold red]" if s["false_negatives"] > 0 else "0")

    console.print(metrics_table)
    console.print(f"\n[bold green]Eval report saved to:[/bold green] [yellow]{json_path.resolve()}[/yellow]")
    console.print(f"[bold green]HTML report saved to:[/bold green] [yellow]{html_path.resolve()}[/yellow]\n")


if __name__ == "__main__":
    app()
