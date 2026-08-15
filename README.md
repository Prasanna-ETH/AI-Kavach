# OWASP Top 10 LLM Security Scanner

An automated CLI security scanner designed to test LLM-powered API endpoints for vulnerabilities mapped to the **OWASP Top 10 for LLM Applications** (Prompt Injection, Jailbreak, Sensitive Data Leakage, System Prompt Disclosure).

---

## 🛠️ Requirements & Environment

- **Python 3.11+**
- Managed with [`uv`](https://github.com/astral-sh/uv)
- Dependencies: `httpx`, `typer`, `pyyaml`, `jinja2`, `rich`, `fastapi`, `uvicorn`, `pytest`
- Optional local LLM target: [Ollama](https://ollama.com/) running `qwen2.5:0.5b`

---

## 🚀 Setup & Installation

1. **Clone & Install Dependencies with `uv`:**
   ```bash
   uv sync
   ```

2. **Setup Local Ollama Model (Required for LLM Judge):**

   The LLM judge, multi-turn attacks, and `eval-judge` commands require a running Ollama server with the `qwen2.5:0.5b` model installed.

   ```bash
   # Install and start Ollama (see https://ollama.com/download)
   ollama serve

   # Pull the required model
   ollama pull qwen2.5:0.5b
   ```

   > **Note:** If you only use the heuristic judge (default for single-turn scans without `--use-llm-judge`), Ollama is not required.

---

## 🔧 Troubleshooting

| Error Message | Cause | Fix |
|---|---|---|
| `Cannot connect to Ollama at http://localhost:11434` | Ollama server is not running | Run `ollama serve` in a separate terminal |
| `Ollama model 'qwen2.5:0.5b' is not installed` | Model hasn't been pulled | Run `ollama pull qwen2.5:0.5b` |
| `LLM Judge Unavailable` (CLI error at startup) | Health check detected Ollama/model issue | Follow the actionable message printed by the CLI |
| All judge results show `heuristic_fallback_llm_error` | LLM judge calls are failing at runtime | Check Ollama is running, model is pulled, and firewall allows localhost:11434 |

---

## 💻 Usage & Examples

### 1. Launch Vulnerable Target Application

Start the included vulnerable target endpoint at `http://localhost:5000/api/chat`:
```bash
uv run python targets/vulnerable_ollama_wrapper.py
```

### 2. Run Single-Turn Security Scan

Execute single-turn scan with `--i-have-permission`:
```powershell
uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --i-have-permission
```

### 3. Run Multi-Turn Adversarial Attack Scan

Execute automated Red-Team multi-turn social engineering & escalation attacks:
```powershell
uv run scanner scan-multiturn --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --attacker-model qwen2.5:0.5b --max-turns 4 --i-have-permission
```

> **Note for PowerShell users:** In PowerShell, line continuation uses the backtick character (`` ` ``), **not** backslash (`\`). If splitting across lines in PowerShell, use `` ` `` at the end of each line.

### Options & Parameters

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--url` | `-u` | Target API endpoint URL | *(Required)* |
| `--body-template` | `-b` | JSON body string with `{{PROMPT}}` | *(Required)* |
| `--response-field` | `-r` | Dotted-path JSON response key | `message.content` |
| `--auth-header` | `-a` | HTTP Header string (e.g. `"Authorization: Bearer key"`) | None |
| `--packs` | `-p` | Comma-separated packs (`prompt_injection,jailbreak,sensitive_data_leak`) | All packs |
| `--delay` | `-d` | Inter-request delay in seconds | `0.5` |
| `--i-have-permission` | | Safety authorization gate | `False` *(Required)* |
| `--use-llm-judge` | | Force local LLM judging for all payloads | `False` |
| `--output-dir` | `-o` | Report destination folder | `scan_results` |

---

## 🧪 Running Unit Tests

Run the test suite with `pytest`:
```bash
uv run pytest
```

---

## 📊 Reports

The scan results are automatically generated in `scan_results/`:
- **`scan_results/report.html`**: Visual dashboard rendered via Jinja2 with OWASP tags, severity badges, and payload details.
- **`scan_results/report.json`**: Structured JSON data suitable for CI/CD pipeline consumption.
