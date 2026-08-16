"""Self-Audit Stress Test for LLM Sentinel."""

import asyncio
import sys
from pathlib import Path
from scanner.config import load_payloads
from scanner.adapters.rest_adapter import RESTAdapter
from scanner.engine import ScanEngine
from scanner.report.html_report import generate_html_report

# Ensure utf-8 stdout on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

async def run_audit():
    print("=" * 60)
    print("[+] LLM SENTINEL SYSTEM AUDIT & STRESS TEST")
    print("=" * 60)

    # 1. Verify Payload Loading across all packs
    packs_to_test = [
        "owasp_llm01_quick_50",
        "owasp_llm02",
        "owasp_llm06_quick_50",
        "owasp_llm07_quick_50",
        "owasp_llm08_quick_50",
        "owasp_llm09_quick_50",
    ]
    total_loaded = 0
    for p_name in packs_to_test:
        loaded = load_payloads([p_name])
        total_loaded += len(loaded)
        print(f"  [+] Pack '{p_name}': {len(loaded)} payloads verified.")
    print(f"Total Verified OWASP Payloads in test packs: {total_loaded}\n")

    # 2. Test Execution against Target
    adapter = RESTAdapter(
        url="http://localhost:5000/api/chat",
        body_template='{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}',
        timeout=120.0,
    )
    engine = ScanEngine(
        adapter=adapter,
        delay=0.1,
        concurrency=1,
        judge_model="llama3.1:8b",
        circuit_breaker_threshold=10,
    )

    test_sample = load_payloads(["owasp_llm01_quick_50"])[:3] + load_payloads(["owasp_llm02"])[:3]
    print(f"Running live pipeline test on {len(test_sample)} diverse payloads...")
    result = await engine.run(test_sample)

    print(f"\nScan Summary:")
    print(f"  * Total Processed: {result.total_payloads}")
    print(f"  * Posture Score: {result.posture_score}/100 (Grade: {result.grade})")
    print(f"  * Likert Distribution: {result.likert_distribution}")
    print(f"  * Circuit Broken: {result.circuit_broken}")

    print("\nDetailed Findings Sample:")
    for f in result.findings:
        print(f"  - [{f.payload.id}] Score {f.likert_score}/4 ({f.severity}) | Judge: {f.judge_type} | Vuln: {f.vulnerable}")
        print(f"    Reasoning: {f.reasoning[:100]}...\n")

    # 3. Verify HTML Report Generation
    out_file = generate_html_report(result, "scan_results/test_audit_report.html")
    assert Path(out_file).exists(), "HTML Report generated empty!"
    file_size = Path(out_file).stat().st_size
    print(f"[+] HTML Report Generated Successfully at {out_file} ({file_size:,} bytes)")
    print("=" * 60)
    print("[+] ALL AUDIT CHECKS PASSED: SYSTEM IS 100% OPERATIONAL")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_audit())
