# 🛡️ Asfalis LLM Sentinel — Python Library & CI/CD Security Hook

> **Automated AI/LLM Security Auditor & Vulnerability Scanner for CI/CD Pipelines**

Convert your AI security scanning into a 1-line Python SDK call or an automated CI/CD pipeline quality gate (GitHub Actions, GitLab CI, Jenkins, Pre-commit hooks).

---

## 📦 Directory Overview (`/library`)

```
d:\Final - CTS\library\
├── __init__.py           # Python package exports (LLMSentinel, ScanConfig, scan_target)
├── client.py             # Core Python SDK client & SARIF / JUnit / Markdown exporters
├── cli_hook.py           # Command-line entry point & build-break gate script
├── .pre-commit-hooks.yaml# Pre-commit hook integration definition
├── pyproject.toml        # Library packaging configuration
├── setup.py              # Setuptools installer
└── github_action/
    └── action.yml        # Reusable GitHub Action step definition
```

---

## 🚀 Quick Start — How to Use the Library

### 1. Installation

Install locally or in your CI/CD runner:

```bash
cd library
pip install -e .
```

Or install directly from git:

```bash
pip install git+https://github.com/Prasanna-ETH/Final-CTS---AI-LLM-Scanner.git#subdirectory=library
```

---

### 2. Python SDK Usage (3-Line Audit)

Add security scanning directly into your automated test suites (`pytest` or Python scripts):

```python
from library import LLMSentinel, ScanConfig

# Initialize scanner for target endpoint
scanner = LLMSentinel(
    target_url="http://localhost:5000/chat",
    target_type="rest",
    fail_on_severity="HIGH"
)

# Run security audit
report = scanner.run_audit()

# Print executive summary
print(report.summary())

# Export reports for CI tools
report.save_sarif("results.sarif")       # GitHub Code Scanning
report.save_junit_xml("results.xml")    # Jenkins / GitLab CI
report.save_markdown("security.md")      # GitHub Job Summary

# Assert security gate passes
assert report.passed_gate, "AI Security Audit Failed: Vulnerabilities detected!"
```

---

### 3. CLI Hook Usage (Command Line & Build Gate)

Run the CLI hook in any pipeline script:

```bash
python -m library.cli_hook \
  --target-url "http://localhost:5000/chat" \
  --target-type rest \
  --fail-on HIGH \
  --sarif-out results.sarif \
  --junit-out results.xml \
  --markdown-out security_audit.md
```

#### Exit Codes:
- `0`: Security audit **PASSED** (no vulnerabilities at or above `--fail-on` threshold).
- `1`: Security audit **FAILED** (vulnerabilities identified at or above `--fail-on` threshold, breaking the CI/CD pipeline).

---

### 4. GitHub Actions CI/CD Pipeline Integration

Add the following workflow file to `.github/workflows/ai-security-scan.yml` in your repository:

```yaml
name: AI LLM Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  llm-security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Start Target Application (Background)
        run: |
          python targets/vulnerable_ollama_wrapper.py &
          sleep 5

      - name: Run Asfalis LLM Sentinel Audit
        run: |
          python -m library.cli_hook \
            --target-url "http://localhost:5000/chat" \
            --fail-on HIGH \
            --sarif-out results.sarif \
            --markdown-out $GITHUB_STEP_SUMMARY

      - name: Upload SARIF Results to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

---

### 5. GitLab CI Integration

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - security

llm_security_audit:
  stage: security
  image: python:3.10
  script:
    - pip install httpx pyyaml pydantic
    - python -m library.cli_hook --target-url "http://localhost:5000/chat" --fail-on HIGH --junit-out junit.xml
  artifacts:
    when: always
    reports:
      junit: junit.xml
```

---

### 6. Git Pre-Commit Hook Integration

Add to `.pre-commit-config.yaml` in your project root:

```yaml
repos:
  - repo: local
    hooks:
      - id: llm-sentinel-scan
        name: Asfalis LLM Sentinel Security Gate
        entry: python -m library.cli_hook --target-url "http://localhost:5000/chat" --limit 10 --fail-on HIGH
        language: python
        types: [python]
```

---

## 📊 Supported Report Formats

| Format | Output Method | Best Used For |
|---|---|---|
| **SARIF 2.1.0** | `report.save_sarif("results.sarif")` | GitHub Code Scanning Security Tab |
| **JUnit XML** | `report.save_junit_xml("results.xml")` | Jenkins / GitLab CI / Azure DevOps Test Widgets |
| **Markdown** | `report.save_markdown("summary.md")` | GitHub Step Summaries & PR Comments |
| **Console Text** | `print(report.summary())` | Terminal / Build Log Inspection |
