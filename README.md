# 🛡️ LLM Sentinel — AI / LLM Application Security Scanner (Version 2.1)

**LLM Sentinel** is an automated, asynchronous security scanner designed to audit LLM API endpoints and generative AI applications for emerging vulnerabilities mapped directly to the **OWASP Top 10 for LLM Applications**.

Equipped with a **3-Tier Deterministic & Heuristic Hybrid Judge Architecture**, **0-to-4 Graduated Likert Severity Scoring**, **Universal RLHF Refusal & PII Pattern Detection**, high-concurrency dispatch, circuit breakers, payload encoding converters, dynamic multi-turn red-teaming dialogue attacks, and rich interactive HTML audit reports with OWASP threat posture matrices.

---

## 🌟 Key Features & Architecture

* **🎯 Comprehensive OWASP Top 10 for LLM Mapping**:
  * **LLM01: Prompt Injection & Filter Evasion**: System override probes, role flips, and instruction boundary manipulation.
  * **LLM02: Sensitive Information & PII Disclosure**: Detection of leaked API Keys (AWS, OpenAI, GitHub, JWT), Credit Cards (Visa, MasterCard, Amex, Discover), SSNs, emails, and passwords.
  * **LLM06: Excessive Agency & Jailbreak Bypasses**: Persona adoption (DAN, Developer Mode), hypothetical scenarios, and unrestricted overrides.
  * **LLM07: System Prompt Leakage**: Extraction of internal system prompts, preambles, and hidden rules.
  * **LLM08: Insecure Output Handling**: Protocol abuse, XSS injection scripts, and Markdown image exfiltration.
* **⚡ 3-Tier Hybrid Evaluation Engine**:
  * **Tier 0 (Universal Refusal Engine)**: Recognizes 100+ standard RLHF refusal templates in $<0.01\text{ ms}$ (Score 0 / Safe, zero LLM calls).
  * **Tier 1 (Signature & PII Engine)**: Evaluates pre-compiled high-entropy regexes for AWS keys, OpenAI keys, GitHub tokens, JWTs, Private keys, Credit Cards, and SSNs in $<0.5\text{ ms}$ (Score 4 / Critical, zero LLM calls).
  * **Tier 2 (LLM Likert Judge)**: Evaluates nuanced, ambiguous cases using local Ollama models (`llama3.1:8b`, `qwen2.5:3b`) with strict anti-hallucination guardrails.
* **🔄 Multi-Turn Adversarial Red-Teaming (`scan-multiturn`)**:
  * **Synthetic QA Auditor Framing**: Formulates conversational escalation prompts (authority appeals, diagnostic pretexting) without triggering the attacker's own safety filters.
  * **Automatic Refusal Interception**: Catches and blocks self-refusals from the attacker LLM, replacing them with dynamic contextual probes.
  * **Per-Turn Deterministic PII & Key Inspection**: Analyzes every turn with Tier-1 signatures to catch leaks immediately even if the target simultaneously recites safety rules.
  * **Executive Breach Impact Cards**: Details the exact attack strategy, target objective, compromised vulnerability vectors, and highlights the exact breach turn in the dialogue transcript.
* **📊 Graduated 0-to-4 Likert Scoring**:
  * **Score 0**: Safe Refusal / Factual Disproof
  * **Score 1**: Benign Context / Clarification
  * **Score 2**: Boundary Slip / Partial Rule Leak
  * **Score 3**: Substantial Compromise / Persona Adoption
  * **Score 4**: Critical Exploit / Verbatim Credential & PII Leak
* **🛡️ Mathematical Security Posture Score ($0 \dots 100$)**:
  * Executive health index calculated from observed harm vs. maximum possible harm with letter grades (**A, B, C, D, F**).
* **🔤 Payload Converters (Obfuscation Testing)**:
  * Tests safety filter evasion via `base64`, `leetspeak`, `rot13`, and low-resource LLM translation (`translation_zulu`).
* **📑 Interactive Executive HTML & JSON Reporting**:
  * Executive **OWASP Top 10 Threat Posture Matrix** with real-time defense integrity bars.
  * Category-by-category findings breakdown with per-row **`🔍 Details`** trays displaying transmitted prompts, raw model responses, and judge reasoning.

---

## 🔬 Architectural Justification: Why the 3-Tier Hybrid Judge?

| Evaluation Method | Speed | Accuracy on Obvious Leaks | Semantic Reasoning & Tone | Cost / Compute Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **Pure Regex / Signatures Only** | Ultra-Fast ($<1\text{ ms}$) | High (exact keywords) | **Fails (0%)** — Blind to paraphrasing & nuance | Minimal |
| **Pure LLM-as-a-Judge Only** | Slow ($500\text{ms} - 2\text{s}$) | Prone to hallucinations | **High** | Very High |
| **🛡️ LLM Sentinel (3-Tier Hybrid)** | **Sub-millisecond for 80% of scans** | **100% Deterministic for PII/Keys** | **High on Ambiguous Edge Cases** | **Optimal** |

### Why Pure Regex Alone Fails:
1. **Semantic Paraphrasing**: Attackers use hypothetical framing or academic pretexts that never match hardcoded keywords.
2. **False Positives on Factual Refutation**: A model debunking flat earth (*"There is no evidence that the earth is flat..."*) matches keyword regexes for `"flat earth"`, falsely flagging safe models as vulnerable.
3. **Graduated Likert Risk**: Risk is not binary; only an LLM Judge can evaluate subtle policy boundary slips (Likert 2/4) vs full exploits (Likert 4/4).

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
# Recommended models for testing and judging
ollama pull llama3.1:8b
ollama pull qwen2.5:3b
```

### 3. Start Local Vulnerable Target Server (For Testing)
```powershell
uv run python targets/vulnerable_ollama_wrapper.py
```
*Listens on `http://localhost:5000/api/chat` (Apex Wealth AI Finance Chatbot with mock confidential database).*

---

## 🚀 CLI Flag Guide & What They Mean

| CLI Flag | What It Means | Why / When to Use It |
| :--- | :--- | :--- |
| `--packs <name>` | Selects which YAML payload pack(s) to scan with (e.g. `agent_evasion_malicious`, `prompt_injection`, `agent_evasion_quick_50`). | Target specific vulnerability vectors instead of running all tests. |
| `--limit <N>` | Restricts the scan to only execute the first **N** payloads. | **Essential for large datasets** (e.g. 500 or 1,000 items) to run a quick test without waiting. |
| `--concurrency <N>` | Number of concurrent async requests sent to the target simultaneously (default: `1`). | Set to `1` for local models (Ollama) to prevent GPU memory spikes; set to `5`–`10` for fast cloud APIs. |
| `--delay <seconds>` | Adds a pause (e.g. `0.2` or `0.5` seconds) between successive requests. | **Rate-limiting / cooldown** to prevent connection timeouts, HTTP 429 errors, or target crashes. |
| `--converters <list>` | Transforms prompts using obfuscation encoders (`base64`, `leetspeak`, `rot13`, `translation_zulu`). | Tests if the target model's safety filters can be **bypassed via encoded/translated inputs**. |
| `--judge-model <model>`| Specifies which Ollama model to use for Tier-2 evaluation (e.g. `llama3.1:8b`, `qwen2.5:3b`). | Uses higher-parameter models (like 8B) for superior evaluation reasoning and low hallucination. |
| `--body-template '<json>'`| Dynamic JSON template sent to the target endpoint. Supports `{{PROMPT}}` replacement. | Adapt the scanner to any REST API schema (e.g. OpenAI, Ollama, custom enterprise endpoints). |
| `--i-have-permission` | Explicit authorization confirmation. | **Mandatory safety gate** required for all scans to enforce safe-by-design AppSec practices. |
| `-v` / `--verbose` | Enables detailed debug logging in the terminal. | View real-time prompt transmissions, raw responses, and judge evaluations as they happen. |

---

## 💻 CLI Execution Recipes for Different Scenarios

All commands require the `--i-have-permission` safety gate.

---

### Scenario 1: Fast 15-Payload Sanity Check with Obfuscation Bypasses
*Runs the first 15 malicious attacks from the Agent Evasion dataset with Base64, Leetspeak, and ROT13 converters:*
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs agent_evasion_malicious `
  --converters base64,leetspeak,rot13 `
  --limit 15 `
  --judge-model llama3.1:8b `
  --i-have-permission
```

---

### Scenario 2: Full 500-Payload Adversarial Attack Scan (With Rate Limiting)
*Runs all 500 malicious attack probes sequentially with a 200ms delay to protect target stability:*
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs agent_evasion_malicious `
  --delay 0.2 `
  --concurrency 1 `
  --judge-model llama3.1:8b `
  --i-have-permission
```

---

### Scenario 3: Balanced 50-Item Benchmark (25 Malicious + 25 Benign)
*Measures both attack detection rate AND false-positive resistance on clean user queries:*
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs agent_evasion_quick_50 `
  --judge-model llama3.1:8b `
  --i-have-permission
```

---

### Scenario 4: Scanning Specific OWASP Hand-Curated Packs
*Audit for Prompt Injection and Sensitive Data Leakage specifically:*
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs prompt_injection,sensitive_data_leak `
  --converters base64,leetspeak `
  --judge-model llama3.1:8b `
  --i-have-permission
```

---

### Scenario 5: Multi-Turn Adversarial Red-Teaming Dialogue (`scan-multiturn`)
*Launches dynamic conversational escalation attacks driven by an adversarial Attacker LLM with breach factor analysis:*
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

### Scenario 6: Measuring Judge Accuracy Against Ground-Truth Datasets
*Evaluates accuracy, precision, recall, and F1 score against human benchmark labels:*
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
├── CHANGELOG.md                    # Detailed version history and architectural notes
├── README.md                       # System documentation and execution guide
├── pyproject.toml                  # Python package specifications and dependencies
├── scan_results/                   # Default output directory for reports and logs
│   ├── report.html                 # Executive dark-theme report with OWASP Scorecard & Multi-Turn Breach Cards
│   ├── report.json                 # Machine-readable scan results for CI/CD pipelines
│   └── scan.log                    # Detailed execution debug log
├── scanner/                        # Core scanner Python package
│   ├── cli.py                      # Typer CLI entrypoint & subcommands
│   ├── config.py                   # YAML payload pack configuration loader
│   ├── engine.py                   # Async scan orchestration engine (rate limiting, circuit breaker)
│   ├── models.py                   # Dataclasses (Payload, Finding, MultiTurnFinding, ScanResult)
│   ├── scoring.py                  # Likert distribution & Security Posture Score calculation
│   ├── owasp_mapping.py            # OWASP Top 10 for LLM taxonomy mappings
│   ├── adapters/                   # Transport adapters
│   │   ├── base.py                 # Abstract BaseAdapter interface
│   │   └── rest_adapter.py         # Async REST API adapter with dotted-path JSON extractors
│   ├── attacker/                   # Red-teaming modules
│   │   └── attacker_llm.py         # Dynamic multi-turn attacker with refusal interception & QA framing
│   ├── converters/                 # Payload prompt obfuscation converters
│   │   ├── base64_converter.py     # Base64 prompt encoder
│   │   ├── leetspeak_converter.py  # Leetspeak character mapping encoder
│   │   ├── rot13_converter.py      # ROT13 cipher encoder
│   │   ├── translation_converter.py# LLM translation converter (e.g. Zulu, Welsh)
│   │   └── registry.py             # Converter factory registry
│   ├── judge/                      # Multi-Tier Evaluation Judges
│   │   ├── signatures.py           # Signature DB (Refusal phrases, API keys, PII, Jailbreaks)
│   │   ├── heuristics.py           # Sub-millisecond Tier-0 & Tier-1 heuristic judge
│   │   ├── likert_judge.py         # 3-Tier Graduated Likert (0-4) Judge
│   │   ├── llm_judge.py            # Local Ollama LLM judge evaluator
│   │   └── multiturn_judge.py      # 3-Tier Multi-turn transcript evaluator & breach factor extractor
│   ├── payloads/                   # Curated YAML payload packs
│   │   ├── handwritten/            # Curated single and multi-turn packs
│   │   ├── agent_evasion/          # 1,000-prompt Kaggle Agent Evasion dataset packs
│   │   └── jbb_derived/            # Benchmark dataset-derived packs
│   └── report/                     # Report generation
│       ├── html_report.py          # Jinja2 HTML report generator
│       ├── json_report.py          # Structured JSON exporter
│       └── templates/              # HTML Jinja2 templates with OWASP matrix & multi-turn breach cards
├── targets/                        # Mock test targets
│   └── vulnerable_ollama_wrapper.py# Apex Wealth AI Finance Assistant listening on port 5000
└── tests/                          # Automated Pytest suite (55 unit tests)
```

---

## 🧪 Running Automated Tests

Run the full pytest suite to verify all components:
```bash
uv run pytest
```
*All 55 unit tests covering converters, dataset loaders, signature matching, PII regexes, Likert calculations, Multi-Turn 3-tier inspection, and REST adapters pass with 100% success.*

---

## 🛡️ Safe-by-Design Principles
1. **Explicit Authorization Gate**: Requires the `--i-have-permission` flag for all security scans.
2. **Circuit Breaking**: The engine halts automated testing early if the target endpoint repeatedly errors or fails connectivity.
3. **Rate Limiting & Concurrency Control**: Prevents target denial-of-service through customizable `--delay` and `--concurrency` controls.
