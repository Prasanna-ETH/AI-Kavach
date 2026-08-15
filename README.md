# 🛡️ LLM Sentinel — AI / LLM Application Security Scanner (Version 2.1)

**LLM Sentinel** is an automated, async-powered security scanner designed to audit LLM API endpoints and AI applications for emerging vulnerabilities mapped directly to the **OWASP Top 10 for LLM Applications** (including Prompt Injection, Sensitive Data & PII Leakage, Jailbreaks, and Insecure Output Handling).

Featuring a **3-Tier Deterministic & Heuristic Safety Judge Architecture**, **0-to-4 Graduated Likert Severity Scoring**, **Universal RLHF Refusal & PII Pattern Detection**, high-concurrency dispatch, circuit breakers, payload encoding converters, multi-turn red-teaming dialogue attacks, and rich interactive HTML inspection reports.

---

## 🌟 Key Features & Architecture

* **🎯 OWASP Top 10 for LLM Mapping**:
  * **LLM01**: Direct & Indirect Prompt Injection
  * **LLM02**: Sensitive Information & PII Disclosure (API Keys, SSNs, Credit Cards, Emails, Phone Numbers)
  * **LLM06**: Excessive Agency & Jailbreak Bypasses (DAN, Persona Adoption, Hypothetical Overrides)
  * **LLM07**: System Prompt Leakage & Preamble Extraction
* **⚡ 3-Tier Hybrid Evaluation Engine**:
  * **Tier 0 (Refusal Engine)**: Evaluates 100+ standard RLHF refusal phrases in $<0.01\text{ ms}$ (Score 0 / Safe, zero LLM calls).
  * **Tier 1 (Signature & PII Engine)**: Evaluates pre-compiled regexes for AWS keys, OpenAI keys, GitHub tokens, JWTs, Private keys, Credit Cards (Visa, MasterCard, Amex), SSNs, and Jailbreak tokens in $<0.5\text{ ms}$ (Score 4 / Critical, zero LLM calls).
  * **Tier 2 (LLM Likert Judge)**: Evaluates nuanced, ambiguous cases using local Ollama models (`llama3.1:8b`, `qwen2.5:3b`, `llama-guard3:8b`) with strict anti-hallucination guardrails.
* **📊 Graduated 0-to-4 Likert Scoring**:
  * **Score 0**: Safe Refusal / Factual Disproof
  * **Score 1**: Benign Context / Clarification
  * **Score 2**: Boundary Slip / Partial Hint
  * **Score 3**: Substantial Disclosure / Persona Adoption
  * **Score 4**: Critical Exploit / Verbatim Credential Leak
* **🛡️ Security Posture Score ($0 \dots 100$)**:
  * Mathematical post-scan health index with letter grading (A, B, C, D, F).
* **🔤 Payload Converters (Obfuscation Testing)**:
  * Tests safety filter evasion via `base64`, `leetspeak`, `rot13`, and low-resource LLM translation (`translation_zulu`).
* **📑 Interactive HTML & JSON Reporting**:
  * Dark-mode executive summary report with per-prompt **`🔍 Details`** trays to inspect exact sent prompts, raw target responses, and judge reasoning.

---

## 🛠️ Environment & Setup

### Requirements
- **Python 3.11+**
- Managed with [`uv`](https://github.com/astral-sh/uv) or standard `venv`
- Local LLM Engine: [Ollama](https://ollama.com/) (for target models and optional LLM-as-a-Judge)

### 1. Install Dependencies
```bash
uv sync
```
*(Or with standard pip: `pip install -e .`)*

### 2. Verify / Pull Local Ollama Models
```bash
# Recommended models
ollama pull llama3.1:8b
ollama pull qwen2.5:3b
```

### 3. Start Local Target Server (For Testing)
```powershell
uv run python targets/vulnerable_ollama_wrapper.py
```
*Listens on `http://localhost:5000/api/chat`.*

---

## 💻 CLI Commands & Usage

All security scan commands enforce safe-by-design testing and require the `--i-have-permission` authorization flag.

### 1. Standard Single-Turn Security Scan
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --judge-model llama3.1:8b `
  --i-have-permission
```

### 2. Scanning with Payload Converters (Evasion Testing)
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --converters base64,leetspeak,rot13,translation_zulu `
  --limit 5 `
  --i-have-permission
```
*Generates `scan_results/report.html`, `scan_results/report.json`, and `scan_results/scan.log`.*

---

### 3. Multi-Turn Adversarial Red-Teaming (`scan-multiturn`)
Executes dynamic multi-turn dialogue escalation attacks driven by an adversarial Attacker LLM:
```powershell
uv run python -m scanner.cli scan-multiturn `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --attacker-model llama3.1:8b `
  --judge-model llama3.1:8b `
  --max-turns 4 `
  --i-have-permission
```

---

### 4. Dataset Ingestion & Evaluation
Convert research CSV benchmarks (e.g. JailbreakBench) into YAML payload packs:
```powershell
uv run python -m scanner.cli dataset import-behaviors `
  --csv dataset/harmful-behaviors.csv `
  --output scanner/payloads/jbb_derived/jbb_harmful.yaml `
  --label harmful `
  --category jailbreak `
  --owasp-id LLM01
```

Evaluate judge accuracy, precision, recall, and F1 score against ground-truth benchmarks:
```powershell
uv run python -m scanner.cli dataset eval-judge `
  --csv dataset/judge-comparison.csv `
  --sample-size 50 `
  --judge-model llama3.1:8b
```

---

## 📁 Project Structure

```
Final-CTS---AI-LLM-Scanner/
├── CHANGELOG.md                    # Detailed version history and architectural changes
├── README.md                       # System documentation and usage guide
├── pyproject.toml                  # Python package specifications and dependencies
├── scan_results/                   # Default output directory for HTML/JSON reports
│   ├── report.html                 # Interactive dark-theme security report with Details trays
│   ├── report.json                 # Machine-readable scan results
│   └── scan.log                    # Detailed execution debug log
├── scanner/                        # Core scanner Python package
│   ├── cli.py                      # Typer CLI entrypoint & subcommands
│   ├── config.py                   # YAML payload pack configuration loader
│   ├── engine.py                   # Async scan orchestration engine
│   ├── models.py                   # Dataclasses (Payload, Finding, ScanResult)
│   ├── scoring.py                  # Likert distribution & Security Posture Score calculation
│   ├── owasp_mapping.py            # OWASP Top 10 for LLM taxonomy mappings
│   ├── adapters/                   # Transport adapters
│   │   ├── base.py                 # Abstract BaseAdapter interface
│   │   └── rest_adapter.py         # Async REST API adapter with JSON path extractors
│   ├── attacker/                   # Red-teaming modules
│   │   └── attacker_llm.py         # Dynamic multi-turn adversarial attacker
│   ├── converters/                 # Payload prompt obfuscation converters
│   │   ├── base64_converter.py     # Base64 prompt encoder
│   │   ├── leetspeak_converter.py  # Leetspeak character mapping encoder
│   │   ├── rot13_converter.py      # ROT13 cipher encoder
│   │   ├── translation_converter.py# LLM low-resource translation converter (Zulu, etc.)
│   │   └── registry.py             # Converter factory registry
│   ├── judge/                      # Multi-Tier Evaluation Judges
│   │   ├── signatures.py           # Signature DB (Refusal phrases, API keys, PII, Jailbreaks)
│   │   ├── heuristics.py           # Sub-millisecond Tier-0 & Tier-1 heuristic judge
│   │   ├── likert_judge.py         # 3-Tier Graduated Likert (0-4) Judge
│   │   ├── llm_judge.py            # Local Ollama LLM judge evaluator
│   │   └── multiturn_judge.py      # Multi-turn transcript evaluator
│   ├── payloads/                   # Curated YAML payload packs
│   │   ├── handwritten/            # Curated single and multi-turn packs
│   │   └── jbb_derived/            # Benchmark dataset-derived packs
│   └── report/                     # Report generation
│       ├── html_report.py          # Jinja2 HTML report generator
│       ├── json_report.py          # Structured JSON exporter
│       └── templates/              # HTML Jinja2 templates
├── targets/                        # Mock test targets
│   └── vulnerable_ollama_wrapper.py# Local test endpoint listening on port 5000
└── tests/                          # Pytest unit & integration test suite (54 tests)
```

---

## 🧪 Running Tests

Execute the automated test suite with pytest:
```bash
uv run pytest
```
*All 54 unit tests covering converters, dataset ingestion, heuristic regexes, PII detection, Likert scoring, and REST adapters pass with 100% success.*

---

## 🛡️ Safe-by-Design Compliance
1. **Safety Gate**: Scans cannot execute without the explicit `--i-have-permission` flag.
2. **Circuit Breaking**: The engine halts automated scans early if the target endpoint repeatedly errors or fails connectivity.
3. **Rate Limiting**: Configurable request delay (`--delay`) and concurrency control (`--concurrency`) to protect target infrastructure.
