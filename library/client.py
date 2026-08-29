"""Asfalis LLM Sentinel Python SDK & CI/CD Engine Integration Library.

Provides programmatic access to AI/LLM security audits, report generation (SARIF 2.1.0, JUnit XML, Markdown),
and CI/CD build failure gate evaluations.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Ensure parent project modules (scanner) are importable
sys_path_root = str(Path(__file__).parents[1])
if sys_path_root not in sys.path:
    sys.path.insert(0, sys_path_root)

from scanner.adapters.browser_adapter import BrowserAdapter
from scanner.adapters.rest_adapter import RESTAdapter
from scanner.config import load_multiturn_payloads, load_payloads
from scanner.judge.likert_judge import LikertJudge
from scanner.models import Finding, Payload, ScanResult

logger = logging.getLogger("sentinel.library")


@dataclass
class ScanConfig:
    """Configuration options for CI/CD security audit runs."""
    target_url: str
    target_type: str = "rest"  # 'rest' or 'browser'
    scan_mode: str = "single"   # 'single', 'multiturn', 'converter'
    packs: List[str] = field(default_factory=lambda: ["prompt_injection", "jailbreak", "sensitive_data_leak", "system_prompt"])
    auth_header: Optional[str] = None
    body_template: Optional[str] = '{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
    response_field: Optional[str] = None
    input_selector: Optional[str] = "textarea"
    send_button_selector: Optional[str] = "button[type='submit']"
    response_selector: Optional[str] = None
    converters: List[str] = field(default_factory=lambda: ["base64", "rot13", "leetspeak"])
    use_llm_judge: bool = True
    judge_model: str = "qwen2.5:3b"
    ollama_url: str = "http://localhost:11434/api/chat"
    concurrency: int = 2
    delay: float = 0.0
    limit: Optional[int] = None
    fail_on_severity: str = "HIGH"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'


@dataclass
class ScanReport:
    """Encapsulates scan findings, metrics, and CI/CD export generators."""
    config: ScanConfig
    findings: List[Finding]
    start_time: datetime
    end_time: datetime
    total_payloads: int
    vulnerable_count: int
    severity_counts: Dict[str, int]
    likert_distribution: Dict[str, int]
    passed_gate: bool

    def summary(self) -> str:
        """Return a human-readable text summary of security audit results."""
        status = "PASSED" if self.passed_gate else "FAILED (Security Gate Violation)"
        return (
            f"====================================================\n"
            f" ASFALIS LLM SENTINEL - SECURITY AUDIT REPORT       \n"
            f"====================================================\n"
            f"Target URL     : {self.config.target_url}\n"
            f"Target Type    : {self.config.target_type.upper()}\n"
            f"Status Gate    : {status}\n"
            f"Total Vectors  : {self.total_payloads}\n"
            f"Vulnerabilities: {self.vulnerable_count}\n"
            f"Severities     : CRITICAL={self.severity_counts.get('CRITICAL',0)}, "
            f"HIGH={self.severity_counts.get('HIGH',0)}, "
            f"MEDIUM={self.severity_counts.get('MEDIUM',0)}, "
            f"LOW={self.severity_counts.get('LOW',0)}\n"
            f"====================================================\n"
        )

    def to_sarif(self) -> Dict[str, Any]:
        """Export findings to SARIF 2.1.0 format for GitHub Code Scanning tab integration."""
        rules = []
        results = []

        seen_rules = set()

        for idx, f in enumerate(self.findings):
            if not f.vulnerable:
                continue

            owasp = getattr(f, 'owasp_id', getattr(f.payload, 'owasp_id', 'LLM01'))
            cat = getattr(f, 'category', getattr(f.payload, 'category', 'Security Vulnerability'))
            pid = getattr(f, 'payload_id', getattr(f.payload, 'id', f'VULN-{idx+1}'))
            p_text = getattr(f, 'prompt', getattr(f.payload, 'prompt', ''))

            rule_id = f"LLM-VULN-{owasp}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": cat,
                    "shortDescription": {"text": f"OWASP {owasp}: {cat}"},
                    "fullDescription": {"text": f.reasoning},
                    "defaultConfiguration": {
                        "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning"
                    },
                    "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                })

            results.append({
                "ruleId": rule_id,
                "message": {"text": f"[{f.severity}] Likert Score {f.likert_score}/4: {f.reasoning}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.config.target_url},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "payload_id": pid,
                    "likert_score": f.likert_score,
                    "confidence": f.confidence,
                    "judge_type": f.judge_type,
                    "prompt_sample": p_text[:150],
                }
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Asfalis LLM Sentinel",
                        "version": "2.2.0",
                        "informationUri": "https://github.com/Prasanna-ETH/Final-CTS---AI-LLM-Scanner",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

    def save_sarif(self, path: Union[str, Path] = "results.sarif") -> Path:
        """Write SARIF report to JSON file."""
        out_path = Path(path)
        sarif_data = self.to_sarif()
        out_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        return out_path

    def to_junit_xml(self) -> str:
        """Export findings to JUnit XML for Jenkins / GitLab CI test report widgets."""
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="LLM_Security_Audit" tests="{self.total_payloads}" failures="{self.vulnerable_count}" timestamp="{self.start_time.isoformat()}">'
        ]
        for f in self.findings:
            owasp = getattr(f, 'owasp_id', getattr(f.payload, 'owasp_id', 'LLM01'))
            cat = getattr(f, 'category', getattr(f.payload, 'category', 'Security Vulnerability'))
            pid = getattr(f, 'payload_id', getattr(f.payload, 'id', 'VULN'))
            p_text = getattr(f, 'prompt', getattr(f.payload, 'prompt', ''))

            classname = f"OWASP_{owasp}"
            name = f"{pid}_{cat}"
            xml_lines.append(f'  <testcase classname="{classname}" name="{name}">')
            if f.vulnerable:
                msg = f"Vulnerability Identified (Likert {f.likert_score}/4 - {f.severity})"
                detail = f"Prompt: {p_text}\nReasoning: {f.reasoning}\nResponse: {f.response_text[:300]}"
                xml_lines.append(f'    <failure message="{msg}">{json.dumps(detail)}</failure>')
            xml_lines.append('  </testcase>')
        xml_lines.append('</testsuite>')
        return "\n".join(xml_lines)

    def save_junit_xml(self, path: Union[str, Path] = "results.xml") -> Path:
        """Write JUnit XML report to file."""
        out_path = Path(path)
        out_path.write_text(self.to_junit_xml(), encoding="utf-8")
        return out_path

    def to_markdown(self) -> str:
        """Export findings to GitHub Job Summary Markdown report."""
        status_badge = "PASSED" if self.passed_gate else "FAILED"
        md = [
            f"# Asfalis LLM Sentinel - Security Audit Summary",
            f"",
            f"**Target URL:** `{self.config.target_url}` | **Target Type:** `{self.config.target_type.upper()}` | **Security Gate:** {status_badge}",
            f"",
            f"### Audit Summary",
            f"- **Total Payloads Tested:** `{self.total_payloads}`",
            f"- **Vulnerabilities Identified:** `{self.vulnerable_count}`",
            f"- **Severity Breakdown:** CRITICAL: `{self.severity_counts.get('CRITICAL',0)}` | HIGH: `{self.severity_counts.get('HIGH',0)}` | MEDIUM: `{self.severity_counts.get('MEDIUM',0)}` | LOW: `{self.severity_counts.get('LOW',0)}`",
            f"",
            f"### Vulnerable Findings",
            f"| Payload ID | OWASP ID | Category | Severity | Likert Score | Confidence | Judge |",
            f"|---|---|---|---|---|---|---|",
        ]

        vuln_findings = [f for f in self.findings if f.vulnerable]
        if not vuln_findings:
            md.append("| _None_ | _None_ | _No vulnerabilities detected_ | _SAFE_ | 0/4 | 100% | `refusal_engine` |")
        else:
            for f in vuln_findings:
                owasp = getattr(f, 'owasp_id', getattr(f.payload, 'owasp_id', 'LLM01'))
                cat = getattr(f, 'category', getattr(f.payload, 'category', 'Security Vulnerability'))
                pid = getattr(f, 'payload_id', getattr(f.payload, 'id', 'VULN'))
                md.append(f"| `{pid}` | `{owasp}` | {cat} | **{f.severity}** | `{f.likert_score}/4` | `{int(f.confidence*100)}%` | `{f.judge_type}` |")

        return "\n".join(md)

    def save_markdown(self, path: Union[str, Path] = "security_audit.md") -> Path:
        """Write Markdown report to file."""
        out_path = Path(path)
        out_path.write_text(self.to_markdown(), encoding="utf-8")
        return out_path


class LLMSentinel:
    """Main Python SDK client for Asfalis LLM Sentinel."""

    def __init__(self, config: Optional[ScanConfig] = None, **kwargs) -> None:
        if config is not None:
            self.config = config
        else:
            self.config = ScanConfig(**kwargs)

    async def run_audit_async(self) -> ScanReport:
        """Execute automated security audit asynchronously against the target URL."""
        cfg = self.config
        start_time = datetime.now(timezone.utc)

        # 1. Initialize Adapter
        if cfg.target_type == "browser":
            adapter = BrowserAdapter(
                target_url=cfg.target_url,
                input_selector=cfg.input_selector or "textarea",
                send_button_selector=cfg.send_button_selector,
                response_selector=cfg.response_selector,
                auth_header=cfg.auth_header,
            )
        else:
            headers = {"Content-Type": "application/json"}
            if cfg.auth_header:
                if ":" in cfg.auth_header:
                    hk, hv = cfg.auth_header.split(":", 1)
                    headers[hk.strip()] = hv.strip()
                elif cfg.auth_header.startswith("Bearer "):
                    headers["Authorization"] = cfg.auth_header.strip()
                else:
                    headers["Authorization"] = f"Bearer {cfg.auth_header.strip()}"

            adapter = RESTAdapter(
                url=cfg.target_url,
                body_template=cfg.body_template or '{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
                response_field=cfg.response_field or "message.content",
                headers=headers,
            )

        # 2. Initialize Judge
        judge = LikertJudge(
            ollama_url=cfg.ollama_url,
            model=cfg.judge_model,
            timeout=90.0,
        )

        # 3. Load Payloads
        if cfg.scan_mode == "multiturn":
            raw_payloads = load_multiturn_payloads(pack_names=cfg.packs)
        else:
            raw_payloads = load_payloads(pack_names=cfg.packs)

        if cfg.limit and cfg.limit > 0:
            raw_payloads = raw_payloads[:cfg.limit]

        findings: List[Finding] = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        likert_dist = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}

        try:
            for payload in raw_payloads:
                if isinstance(payload, Payload):
                    resp_text = await adapter.send(payload.prompt)
                    finding = await judge.evaluate(payload, resp_text)
                    findings.append(finding)

                    if finding.vulnerable:
                        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
                    else:
                        severity_counts["LOW"] += 1

                    score_key = getattr(finding, "likert_score", 0)
                    likert_dist[score_key] = likert_dist.get(score_key, 0) + 1

                if cfg.delay > 0:
                    await asyncio.sleep(cfg.delay)

        finally:
            if hasattr(adapter, "close"):
                await adapter.close()

        end_time = datetime.now(timezone.utc)
        vulnerable_count = sum(1 for f in findings if f.vulnerable)

        # Evaluate CI/CD Failure Threshold
        fail_levels = {
            "CRITICAL": ["CRITICAL"],
            "HIGH": ["CRITICAL", "HIGH"],
            "MEDIUM": ["CRITICAL", "HIGH", "MEDIUM"],
            "LOW": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "NONE": []
        }
        target_levels = fail_levels.get(cfg.fail_on_severity.upper(), ["CRITICAL", "HIGH"])
        passed_gate = not any(
            f.vulnerable and f.severity in target_levels
            for f in findings
        )

        return ScanReport(
            config=cfg,
            findings=findings,
            start_time=start_time,
            end_time=end_time,
            total_payloads=len(raw_payloads),
            vulnerable_count=vulnerable_count,
            severity_counts=severity_counts,
            likert_distribution=likert_dist,
            passed_gate=passed_gate,
        )

    def run_audit(self) -> ScanReport:
        """Synchronous wrapper to execute automated security audit."""
        return asyncio.run(self.run_audit_async())


def scan_target(target_url: str, fail_on: str = "HIGH", **kwargs) -> ScanReport:
    """Quick helper function to run an audit against a target URL in 1 line of Python code."""
    client = LLMSentinel(target_url=target_url, fail_on_severity=fail_on, **kwargs)
    return client.run_audit()
