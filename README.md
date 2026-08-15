# 🛡️ LLM Sentinel — OWASP Top 10 for LLM Applications Security Scanner

**LLM Sentinel** is an automated, async-powered security scanner designed to audit LLM API endpoints for vulnerabilities mapped to the **OWASP Top 10 for LLM Applications** (including Prompt Injection, Sensitive Data Leakage, and Jailbreak Bypasses). Featuring high-concurrency dispatch, exponential backoff retries, circuit breaking, multi-turn red-teaming dialogue attacks, payload encoding converters, and offline judge accuracy evaluation against JailbreakBench benchmarks, it provides comprehensive security assessment for LLM application operators.

---

## 🛠️ Environment & Setup

### Requirements
- **Python 3.11+**
- Managed with [`uv`](https://github.com/astral-sh/uv)
- Local LLM Runner: [Ollama](https://ollama.com/) (for local judging, multi-turn driver, and translation converters)

### 1. Install Dependencies
```bash
uv sync
```

### 2. Pull Required Ollama Models
```bash
# Pull model used for LLM judging and red-team driving (default: qwen2.5:0.5b)
ollama pull qwen2.5:0.5b
```

### 3. Start Local Vulnerable Target Server (for testing)
The repository includes a local vulnerable mock LLM target for testing:
```bash
uv run .\targets\vulnerable_ollama_wrapper.py
```
*Listens on `http://localhost:5000/api/chat`.*

---

## 💻 CLI Commands & Usage Examples

All commands require the `--i-have-permission` safety gate flag.

### 1. Single-Turn Security Scan (`scan`)
Executes single-turn security payloads against target endpoint.

```powershell
.venv\Scripts\python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"prompt":"{{PROMPT}}"}' `
  --i-have-permission
```

#### Running with Payload Converters (Encoding Bypasses):
Test whether safety filters are bypassed via Base64, Leetspeak, ROT13, or LLM-based translation:
```powershell
.venv\Scripts\python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"prompt":"{{PROMPT}}"}' `
  --converters base64,leetspeak,rot13,translation_zulu `
  --limit 5 `
  --i-have-permission
```
*Produces `scan_results/report.html`, `scan_results/report.json`, and `scan_results/scan.log`.*

---

### 2. Multi-Turn Adversarial Red-Teaming (`scan-multiturn`)
Executes dynamic multi-turn dialogue escalation attacks driven by an adversarial Attacker LLM.

```powershell
.venv\Scripts\python -m scanner.cli scan-multiturn `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"prompt":"{{PROMPT}}"}' `
  --attacker-model qwen2.5:0.5b `
  --judge-model qwen2.5:0.5b `
  --max-turns 4 `
  --i-have-permission
```
*Produces `scan_results/multiturn_report.json` and interactive Jinja2 HTML transcript reports.*

---

### 3. Dataset Ingestion (`dataset import-behaviors`)
Converts raw research CSV datasets (e.g. JailbreakBench) into reusable YAML payload packs.

```powershell
.venv\Scripts\python -m scanner.cli dataset import-behaviors `
  --csv dataset/harmful-behaviors.csv `
  --output scanner/payloads/jbb_derived/jbb_harmful.yaml `
  --label harmful `
  --category jailbreak `
  --owasp-id LLM01
```

---

### 4. Dataset Behaviors Scan (`dataset scan-behaviors`)
Runs security scans using dataset-derived payload packs and reports jailbreak success / false-positive metrics.

```powershell
.venv\Scripts\python -m scanner.cli dataset scan-behaviors `
  --url "http://localhost:5000/api/chat" `
  --pack jbb_harmful.yaml `
  --limit 10 `
  --i-have-permission
```

---

### 5. Judge Accuracy Evaluation (`dataset eval-judge`)
Measures judge accuracy, precision, recall, and F1 score against human ground-truth datasets (`judge-comparison.csv`).

```powershell
.venv\Scripts\python -m scanner.cli dataset eval-judge `
  --csv dataset/judge-comparison.csv `
  --sample-size 50 `
  --judge-model qwen2.5:0.5b
```

---

## 📁 Project Structure Overview

```
Final - CTS/
├── CHANGELOG.md                    # Timeline of development and architectural history
├── README.md                       # Comprehensive system documentation
├── pyproject.toml                  # Project metadata and dependencies
├── scan_results/                   # Default output folder for HTML/JSON reports and scan.log
├── scanner/                        # Main scanner Python package
│   ├── __init__.py                 # Package initialization
│   ├── cli.py                      # Typer CLI application entry point & subcommands
│   ├── config.py                   # Recursive YAML payload pack configuration loader
│   ├── engine.py                   # Async scan orchestration engine (backoff, circuit breaker, converters)
│   ├── models.py                   # Dataclasses (Payload, Finding, MultiTurnFinding, ScanResult)
│   ├── owasp_mapping.py            # OWASP Top 10 for LLM Applications category definitions
│   ├── adapters/                   # API connection adapters
│   │   ├── base.py                 # Abstract BaseAdapter interface
│   │   └── rest_adapter.py         # Async httpx REST API adapter
│   ├── attacker/                   # Red-teaming driver modules
│   │   └── attacker_llm.py         # Multi-turn adversarial driver LLM
│   ├── common/                     # Shared client utilities
│   │   └── ollama_client.py        # Single shared HTTP client helper for Ollama model calls
│   ├── converters/                 # Payload prompt obfuscation converters
│   │   ├── base.py                 # Abstract Converter base class
│   │   ├── base64_converter.py     # Base64 prompt encoder
│   │   ├── leetspeak_converter.py  # Leetspeak character mapping encoder
│   │   ├── rot13_converter.py      # ROT13 cipher encoder
│   │   ├── translation_converter.py# LLM translation converter (e.g. Zulu, Welsh)
│   │   └── registry.py             # Converter factory function get_converter()
│   ├── datasets/                   # Dataset loaders and converters
│   │   ├── csv_loader.py           # JailbreakBench CSV parser
│   │   └── csv_to_yaml.py          # CSV to YAML payload converter
│   ├── judge/                      # Vulnerability evaluation judges
│   │   ├── heuristics.py           # Fast keyword & pattern matching heuristic judge
│   │   ├── llm_judge.py            # Local Ollama LLM judge evaluator
│   │   └── multiturn_judge.py      # Multi-turn transcript evaluator
│   ├── payloads/                   # YAML payload pack library
│   │   ├── handwritten/            # Hand-curated single and multi-turn packs
│   │   ├── jbb_derived/            # Benchmark dataset-derived packs
│   │   └── README.md               # Payload library documentation
│   └── report/                     # Reporting generators
│       ├── eval_report.py          # Judge accuracy metrics computer
│       ├── html_report.py          # Jinja2 HTML report generator
│       ├── json_report.py          # Structured JSON report exporter
│       └── templates/              # Jinja2 HTML templates
├── targets/                        # Mock test targets
│   └── vulnerable_ollama_wrapper.py# Vulnerable mock target server listening on port 5000
└── tests/                          # Pytest test suite
    ├── test_converters.py          # Unit tests for converters module
    ├── test_dataset_ingestion.py   # Ingestion tests
    ├── test_engine.py             # Engine concurrency and backoff tests
    ├── test_heuristics.py         # Heuristic judge tests
    ├── test_llm_judge.py          # LLM judge tests
    ├── test_multiturn.py          # Multi-turn attack tests
    └── test_rest_adapter.py       # REST adapter tests
```

---

## 📝 How to Add a New Payload Pack

Create a `.yaml` file under `scanner/payloads/handwritten/` following this schema:

```yaml
payloads:
  - id: CUSTOM-001
    category: jailbreak
    owasp_id: LLM06
    prompt: "Your attack prompt text here."
    severity: HIGH
    heuristic_keywords:
      - "keyword match 1"
      - "keyword match 2"
    requires_llm_judge: false
```

---

## 🔧 How to Add a New Converter

1. Create a new file in `scanner/converters/` (e.g. `my_converter.py`) subclassing `Converter`:

```python
from scanner.converters.base import Converter

class MyConverter(Converter):
    @property
    def name(self) -> str:
        return "my_converter"

    async def transform(self, prompt: str) -> str:
        return prompt.upper()  # Your transformation logic
```

2. Register your converter in `scanner/converters/registry.py`:
```python
BUILTIN_CONVERTERS = {
    "base64": Base64Converter,
    "leetspeak": LeetspeakConverter,
    "rot13": Rot13Converter,
    "my_converter": MyConverter,
}
```

---

## ⚠️ Known Limitations

1. **Target Types**: Designed for single-turn and multi-turn HTTP LLM API endpoints. Does not evaluate agentic tool-use loops or multi-agent messaging buses.
2. **Judge Model Dependency**: Accuracy of the LLM Judge depends on the judge model installed. Small local models (e.g., `qwen2.5:0.5b`) provide rapid local evaluation but larger models (e.g., `qwen2.5:7b` or `llama3`) yield higher precision on complex nuances.
3. **Plain-Text Baseline Rule**: Payload converters always execute the plain-text baseline alongside converted variants.
