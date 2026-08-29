"""CLI Hook & CI/CD Gate Command-Line Tool for Asfalis LLM Sentinel.

Usage in CI/CD pipeline / GitHub Actions / Pre-commit:
  python -m library.cli_hook --target-url "http://localhost:5000/chat" --fail-on HIGH --sarif-out results.sarif
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = str(Path(__file__).parents[1])
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from library.client import LLMSentinel, ScanConfig


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Asfalis LLM Sentinel - Automated AI/LLM Security Audit CI/CD Gate"
    )
    parser.add_argument(
        "--target-url",
        required=True,
        help="Target endpoint URL (e.g. http://localhost:5000/chat)"
    )
    parser.add_argument(
        "--target-type",
        choices=["rest", "browser"],
        default="rest",
        help="Target type: rest API or browser widget (default: rest)"
    )
    parser.add_argument(
        "--scan-mode",
        choices=["single", "multiturn", "converter"],
        default="single",
        help="Attack strategy mode (default: single)"
    )
    parser.add_argument(
        "--packs",
        nargs="+",
        default=["prompt_injection", "jailbreak", "sensitive_data_leak", "system_prompt"],
        help="Space-separated list of payload packs to audit"
    )
    parser.add_argument(
        "--auth-header",
        default=None,
        help="Optional authorization header (e.g. 'Bearer sk-xxx' or 'Cookie: sid=xyz')"
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="HIGH",
        help="Minimum severity threshold to fail the build (default: HIGH)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit total number of payload vectors per pack (for fast CI checks)"
    )
    parser.add_argument(
        "--sarif-out",
        default=None,
        help="File path to save SARIF 2.1.0 report (e.g. results.sarif)"
    )
    parser.add_argument(
        "--junit-out",
        default=None,
        help="File path to save JUnit XML report (e.g. results.xml)"
    )
    parser.add_argument(
        "--markdown-out",
        default=None,
        help="File path to save Markdown Summary report (e.g. security_audit.md)"
    )

    args = parser.parse_args()

    config = ScanConfig(
        target_url=args.target_url,
        target_type=args.target_type,
        scan_mode=args.scan_mode,
        packs=args.packs,
        auth_header=args.auth_header,
        fail_on_severity=args.fail_on,
        limit=args.limit,
    )

    print(f"\n[+] Launching Asfalis LLM Sentinel CI/CD Security Audit...")
    print(f"Target: {args.target_url} ({args.target_type.upper()}) | Failure Threshold: {args.fail_on}\n")

    scanner = LLMSentinel(config)
    report = scanner.run_audit()

    print(report.summary())

    # Save export reports if requested
    if args.sarif_out:
        p = report.save_sarif(args.sarif_out)
        print(f"[+] SARIF report exported to: {p}")

    if args.junit_out:
        p = report.save_junit_xml(args.junit_out)
        print(f"[+] JUnit XML report exported to: {p}")

    if args.markdown_out:
        p = report.save_markdown(args.markdown_out)
        print(f"[+] Markdown report exported to: {p}")

    # Enforce CI/CD Exit Code
    if not report.passed_gate:
        print(f"\n[X] SECURITY AUDIT FAILED: Vulnerabilities detected at or above '{args.fail_on}' severity threshold!")
        sys.exit(1)
    else:
        print(f"\n[OK] SECURITY AUDIT PASSED: No security regressions identified above '{args.fail_on}' threshold.")
        sys.exit(0)


if __name__ == "__main__":
    main()
