# 🛡️ LLM Sentinel — AI / LLM Application Security Scanner (Version 2.3)

**LLM Sentinel** is an automated, asynchronous, enterprise-grade security scanner designed to audit LLM API endpoints, autonomous agents, and web-based AI chatbots for vulnerabilities mapped directly to the **OWASP Top 10 for LLM Applications**.

Equipped with a **3-Tier Deterministic & Heuristic Hybrid Judge Architecture**, **0-to-4 Graduated Likert Severity Scoring**, **Dynamic Gitleaks & Microsoft Presidio PII/Secret Engine**, **Universal DLP Engine with Prompt-Echo and Canary-Refusal Disambiguation**, **Universal Protocol Transport (POST JSON, GET URL Query Templating, Headless Playwright Browser Automation)**, high-concurrency dispatch, circuit breakers, payload encoding converters, dynamic multi-turn red-teaming dialogue attacks, and rich interactive HTML audit reports with OWASP threat posture matrices.

---

## 🌟 Key Features & Architecture

* **🎯 Comprehensive Universal OWASP Top 10 for LLM Suites**:
  * **LLM01: Prompt Injection & Filter Evasion**: Universal delimiter escapes, role flips, ChatML/Llama inst token breakouts, and instruction boundary manipulation.
  * **LLM02: Sensitive Information & PII Disclosure**: Universal wildcard data harvesting (SSNs, Credit Cards, Indian Aadhaar & PAN IDs, AWS keys, OpenAI keys, GitHub tokens, JWTs, and database URLs).
  * **LLM06: Excessive Agency & Jailbreak Bypasses**: HarmBench, JailbreakBench, and Malicious Agent Evasion behavioral override probes.
  * **LLM07: System Prompt Leakage**: Preamble extraction, JSON schema inversion, verbatim instruction dumps, and multi-lingual translation bypasses.
  * **LLM08: Insecure Output Handling & PyRIT Exfiltration**: Markdown image exfiltration tags, SVG onload scripts, XSS payloads, command injections (`whoami`), and SSRF parameters.
  * **LLM09: Misinformation, Hallucination & Sycophancy**: Sycophancy persona traps (Anthropic dataset) and fabricated legal/medical hallucination probes.
* **⚡ 3-Tier Hybrid Evaluation Engine**:
  * **Tier 0 (Universal Refusal Engine)**: Recognizes 150+ standard RLHF refusal templates and cloud content filter error responses (Azure, OpenAI, Claude) in $<0.01\text{ ms}$ (Score 0 / Safe, zero LLM calls). Includes full Unicode curly quote normalization and explanatory critique disambiguation.
  * **Tier 1 (Signature, Gitleaks & DLP Engine)**: Evaluates pre-compiled high-entropy regexes from **Gitleaks** (`sources/rules-stable.yml`, 150+ cloud/API secrets) and **Microsoft Presidio** (`sources/pii-stable.yml`, SSNs, Credit Cards with Luhn validation, Indian Aadhaar/PAN, emails, phones) with smart noise filtering (filtering prices `$0.00`, dates, and hex colors).
  * **Tier 2 (LLM Likert Judge)**: Evaluates nuanced, ambiguous cases using local Ollama models (`qwen2.5:3b`, `llama3.1:8b`) with strict anti-hallucination guardrails and context-deflection awareness.
* **🔍 Zero False-Positive Protection Layer**:
  * **Prompt-Echo Exclusion**: Discards matched PII, secrets, or emails if the exact token was present in the attacker's prompt (e.g. `sec-ops@internal-admin.net` in authority pretexting attacks).
  * **Canary Quoting Refusal Filter (`is_canary_echo_in_explanation`)**: Prevents false positive triggers when a target model quotes attack canaries (e.g. `(PRINT_OVERRIDE_FLAG_2026)`) inside an explanatory or refusal sentence.
  * **Context-Deflection Anti-Hallucination Filter**: Overrides hallucinated LLM Judge scores when a model explicitly states it lacks the requested confidential information.
* **🌐 Universal Transport & Protocol Adapters**:
  * **High-Speed REST Scanner (POST JSON)**: Audits remote REST APIs with dotted-path JSON extraction (`choices.0.message.content`, `response`, `content`).
  * **GET URL Query Templating**: Directly audits query parameter endpoints (`--url "http://localhost:5000/get?msg={{PROMPT}}"`) with automatic URL encoding and plain-text response extraction.
  * **Automated Playwright Browser Adapter (`--browser`)**: Interacts with single-page chat web apps, performs Network Response Interception, and computes DOM Snapshot Delta Diffing to discard static headers and footers.
* **🔄 Multi-Turn Adversarial Red-Teaming (`scan-multiturn`)**:
  * **Synthetic QA Auditor Framing**: Formulates conversational escalation prompts (authority appeals, diagnostic pretexting) without triggering the attacker's own safety filters.
  * **Automatic Refusal Interception**: Catches and blocks self-refusals from the attacker LLM, replacing them with dynamic contextual probes.
  * **Per-Turn Deterministic PII & Key Inspection**: Analyzes every turn with Tier-1 signatures to catch leaks immediately.
* **📊 Graduated 0-to-4 Likert Scoring**:
  * **Score 0**: Safe Refusal / Factual Disproof / Content Filter Block
  * **Score 1**: Benign Context / Clarification
  * **Score 2**: Boundary Slip / Partial Rule Leak
  * **Score 3**: Substantial Compromise / Unauthorized Persona (DAN, Jailbreak)
  * **Score 4**: Critical Exploit / Verbatim Credential & PII Leak
* **🛡️ Mathematical Security Posture Score ($0 \dots 100$)**:
  * Executive health index calculated from observed harm vs. maximum possible harm with letter grades (**A, B, C, D, F**).
* **🔤 Payload Converters (Obfuscation Testing)**:
  * Tests safety filter evasion via `base64`, `leetspeak`, `rot13`, and low-resource LLM translation (`translation_zulu`).
* **📑 Interactive Executive HTML, JSON, CSV & SARIF Reporting**:
  * Executive **OWASP Top 10 Threat Posture Matrix** with real-time defense integrity bars.
  * Category-by-category findings breakdown with per-row **`🔍 Details`** trays displaying transmitted prompts, raw model responses, and judge reasoning.
  * Multi-converter comparison view with automated agreement/disagreement tracking.

---

## 🔬 Architectural Justification: Why the 3-Tier Hybrid Judge?

| Evaluation Method | Speed | Accuracy on Obvious Leaks | Semantic Reasoning & Tone | Cost / Compute Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **Pure Regex / Signatures Only** | Ultra-Fast ($<1\text{ ms}$) | High (exact keywords) | **Fails (0%)** — Blind to paraphrasing & nuance | Minimal |
| **Pure LLM-as-a-Judge Only** | Slow ($500\text{ms} - 2\text{s}$) | Prone to hallucinations | **High** | Very High |
| **🛡️ LLM Sentinel (3-Tier Hybrid)** | **Sub-millisecond for 80% of scans** | **100% Deterministic for PII/Keys** | **High on Ambiguous Edge Cases** | **Optimal** |

---

## 🛠️ Environment & Setup

### Requirements
- **Python 3.11+**
- Managed with [`uv`](https://github.com/astral-sh/uv) or standard `venv`
- Local LLM Engine: [Ollama](https://ollama.com/) (for target models and optional LLM-as-a-Judge)
- Chromium Browser (for Playwright testing): `uv run playwright install chromium`

### 1. Install Dependencies
```bash
uv sync
uv run playwright install chromium
```

### 2. Verify / Pull Local Ollama Models
```bash
ollama pull qwen2.5:3b
ollama pull llama3.1:8b
```

### 3. Start Local Vulnerable Target Server (For Testing)
```powershell
uv run python targets/vulnerable_ollama_wrapper.py
```
*Listens on `http://localhost:5000/api/chat` (Enterprise AI Finance Assistant with live web chat UI, connected tools, and confidential RAG database).*

---

## 🌐 Web & API Testing Modes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 WEB APPLICATION TESTING STRATEGIES                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MODE 1: High-Speed Direct REST (POST JSON & GET Query)                     │
│  • Best for: Mass vulnerability audits (50–500 payloads in seconds).        │
│  • Features: 100x faster ($0.2s/prompt), zero browser lag, zero UI noise.  │
│  • Supports POST JSON schemas AND GET URL parameters (?msg={{PROMPT}}).     │
│                                                                             │
│  MODE 2: Automated Headless Browser (--browser)                             │
│  • Best for: Single-page apps (SPAs), web forms, and UI chat interfaces.    │
│  • Features: Automatic session cookies, Network Response Interception, and  │
│    Snapshot Delta Diffing (mathematically discards static footer/menus).    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Mode 1: High-Speed REST & URL Query Scanning

#### A. Standard POST JSON Endpoint:
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs owasp_llm01_quick_50 `
  --limit 10 `
  --concurrency 1 `
  --delay 0.5 `
  --judge-model qwen2.5:3b `
  --i-have-permission
```

#### B. GET Query URL Endpoint (e.g. Chatbots with `?msg=...`):
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/get?msg={{PROMPT}}" `
  --packs owasp_llm01_quick_50 `
  --limit 10 `
  --concurrency 1 `
  --delay 0.5 `
  --judge-model qwen2.5:3b `
  --i-have-permission
```

---

### Mode 2: Automated Headless Browser Scanning (`--browser`)

Simply add `--browser` (or `-B`) and point LLM Sentinel to the target web chat URL:

```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000" `
  --browser `
  --packs owasp_llm01_quick_50 `
  --limit 5 `
  --concurrency 1 `
  --delay 1.0 `
  --judge-model qwen2.5:3b `
  --i-have-permission
```

---

## 🚀 CLI Flag Reference

| CLI Flag | What It Means | Why / When to Use It |
| :--- | :--- | :--- |
| `--packs <name>` | Selects which YAML payload pack(s) to scan with (`owasp_llm01_quick_50`, `agent_evasion_malicious`, `owasp_llm02_quick_50`, `owasp_llm07_quick_50`, etc.). | Target specific vulnerability vectors instead of running all tests. |
| `--limit <N>` | Restricts the scan to only execute the first **N** payloads. | **Essential for large datasets** to run quick targeted audits without waiting. |
| `--concurrency <N>` | Number of concurrent async requests sent to the target simultaneously (default: `1`). | Set to `1` for local models (Ollama); set to `5`–`10` for fast cloud APIs. |
| `--delay <seconds>` | Adds a pause between successive requests (e.g. `0.5` or `1.0` seconds). | **Rate-limiting / cooldown** to prevent connection timeouts or target crashes. |
| `--browser` / `-B` | Enables Playwright browser automation. | Automatically navigates, fills inputs, and scrapes replies from single-page web chats. |
| `--converters <list>` | Transforms prompts using obfuscation encoders (`base64`, `leetspeak`, `rot13`, `translation_zulu`). | Tests if the target model's safety filters can be **bypassed via encoded/translated inputs**. |
| `--judge-model <model>`| Specifies which Ollama model to use for Tier-2 evaluation (`qwen2.5:3b`, `llama3.1:8b`). | Local LLM judge for nuanced semantic scoring. |
| `--auth-header "<hdr>"`| Custom authentication or session header (e.g. `"Authorization: Bearer <key>"` or `"Cookie: session=..."`). | Authenticate against protected REST endpoints and web chat sessions. |
| `--body-template '<json>'`| Dynamic JSON template sent to the target endpoint. Supports `{{PROMPT}}` replacement. | Adapt the scanner to any REST API schema (e.g. OpenAI, Ollama, custom enterprise endpoints). |
| `--response-field "<path>"`| Dotted JSON path to extract the assistant's reply (e.g. `"content"`, `"response"`, `"choices.0.message.content"`). | Extract AI response from any custom JSON structure. |
| `--i-have-permission` | Explicit authorization confirmation. | **Mandatory safety gate** required for all scans to enforce safe-by-design AppSec practices. |
| `-v` / `--verbose` | Enables detailed debug logging in the terminal. | View real-time prompt transmissions, raw responses, and judge evaluations as they happen. |

---

## 💻 Common Execution Recipes

All commands require the `--i-have-permission` safety gate.

---

### Scenario 1: Malicious Agent Evasion Audit with Converters
*Tests obfuscated agent evasion attacks across Base64, ROT13, and Leetspeak:*
```powershell
uv run python -m scanner.cli scan `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --packs agent_evasion_malicious `
  --converters "base64,rot13,leetspeak" `
  --limit 10 `
  --concurrency 1 `
  --judge-model qwen2.5:3b `
  --i-have-permission
```

---

### Scenario 2: Multi-Turn Adversarial Red-Teaming Dialogue (`scan-multiturn`)
*Launches dynamic conversational escalation attacks driven by an adversarial Attacker LLM with breach factor analysis:*
```powershell
uv run python -m scanner.cli scan-multiturn `
  --url "http://localhost:5000/api/chat" `
  --body-template '{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}' `
  --attacker-model qwen2.5:3b `
  --judge-model qwen2.5:3b `
  --max-turns 4 `
  --i-have-permission
```

---

### Scenario 3: Measuring Judge Accuracy Against Ground-Truth Benchmark
*Evaluates accuracy, precision, recall, and F1 score against human benchmark labels:*
```powershell
uv run python -m scanner.cli dataset eval-judge `
  --csv dataset/judge-comparison.csv `
  --sample-size 50 `
  --judge-model qwen2.5:3b
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
│   │   ├── rest_adapter.py         # Async REST API adapter with GET query & dotted-path JSON extractors
│   │   └── playwright_adapter.py   # Headless browser adapter with Network Interception & Delta Diffing
│   ├── attacker/                   # Red-teaming modules
│   │   └── attacker_llm.py         # Dynamic multi-turn attacker with refusal interception & QA framing
│   ├── converters/                 # Payload prompt obfuscation converters
│   │   ├── base64_converter.py     # Base64 prompt encoder
│   │   ├── leetspeak_converter.py  # Leetspeak character mapping encoder
│   │   ├── rot13_converter.py      # ROT13 cipher encoder
│   │   ├── translation_converter.py# LLM translation converter (e.g. Zulu, Welsh)
│   │   └── registry.py             # Converter factory registry
│   ├── judge/                      # Multi-Tier Evaluation Judges
│   │   ├── signatures.py           # Signature DB (Refusals, API keys, PII, prompt-echo exclusion)
│   │   ├── signature_loader.py     # Dynamic Gitleaks (150+ secrets) & Presidio PII database loader
│   │   ├── heuristics.py           # Sub-millisecond Tier-0 & Tier-1 heuristic judge with canary filter
│   │   ├── likert_judge.py         # 3-Tier Graduated Likert (0-4) Judge with Anti-Hallucination rules
│   │   ├── llm_judge.py            # Local Ollama LLM judge evaluator
│   │   └── multiturn_judge.py      # 3-Tier Multi-turn transcript evaluator & breach factor extractor
│   ├── payloads/                   # Curated YAML payload packs
│   │   ├── owasp_top10/            # Curated OWASP Top 10 Universal Suites (LLM01, LLM02, LLM06..LLM09)
│   │   ├── handwritten/            # Curated single and multi-turn packs
│   │   ├── agent_evasion/          # Agent Evasion dataset packs (malicious, quick_50, full)
│   │   └── jbb_derived/            # Benchmark dataset-derived packs
│   └── report/                     # Report generation
│       ├── html_report.py          # Jinja2 HTML report generator
│       ├── json_report.py          # Structured JSON exporter
│       └── templates/              # HTML Jinja2 templates with OWASP matrix & converter comparisons
├── sources/                        # Pre-compiled security signature databases
│   ├── rules-stable.yml            # 150+ enterprise cloud secrets & tokens (Gitleaks)
│   └── pii-stable.yml              # Enterprise PII pattern database (Microsoft Presidio)
├── targets/                        # Mock test targets
│   └── vulnerable_ollama_wrapper.py# Enterprise AI Finance Assistant with web UI & REST API on port 5000
└── tests/                          # Automated Pytest suite (75 unit tests, 100% passing)
```

---

## 🧪 Running Automated Tests

Run the full pytest suite to verify all components:
```bash
uv run pytest
```
*All 75 unit tests covering converters, dataset loaders, signature matching, Gitleaks & Presidio loaders, prompt-echo filters, Likert calculations, Multi-Turn 3-tier inspection, Playwright Delta Diffing, and GET/POST REST adapters pass with 100% success.*

---

## 🛡️ Safe-by-Design Principles
1. **Explicit Authorization Gate**: Requires the `--i-have-permission` flag for all security scans.
2. **Circuit Breaking**: The engine halts automated testing early if the target endpoint repeatedly errors or fails connectivity.
3. **Rate Limiting & Concurrency Control**: Prevents target denial-of-service through customizable `--delay` and `--concurrency` controls.
