uv run scanner scan-multiturn --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --attacker-model qwen2.5:0.5b --max-turns 4 --i-have-permission
uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --i-have-permission

# Scanner CLI Capabilities Overview

The scanner CLI provides two primary scanning modes:

* `scanner scan`: Single-Turn Security Scan — fast, concurrent scanning that tests direct attack prompts against target LLM endpoints.
* `scanner scan-multiturn`: Multi-Turn Adversarial Attack Scan — automated Red-Team AI driving multi-stage social engineering, rapport-building, and hypothetical escalation dialogues.

## 1. `scanner scan` — Single-Turn Scan

Tests target endpoints against single-turn attack payloads across OWASP categories:

* **LLM01:** Prompt Injection
* **LLM02:** Sensitive Data Leak
* **LLM06:** Jailbreak

### Syntax

```powershell
uv run scanner scan --url <TARGET_URL> --body-template <JSON_TEMPLATE> [OPTIONS] --i-have-permission
```

### Options & Parameters

| Option                | Short | Type   | Default           | Description                                                                            |
| --------------------- | ----- | ------ | ----------------- | -------------------------------------------------------------------------------------- |
| `--url`               | `-u`  | string | Required          | Target API endpoint URL, e.g. `http://localhost:5000/api/chat`.                        |
| `--body-template`     | `-b`  | string | Required          | JSON body string template containing the `{{PROMPT}}` placeholder.                     |
| `--response-field`    | `-r`  | string | `message.content` | Dotted-path key to extract the model's response text from JSON.                        |
| `--auth-header`       | `-a`  | string | None              | Custom HTTP headers, e.g. `-a "Authorization: Bearer token"` or `-a "x-api-key: 123"`. |
| `--packs`             | `-p`  | string | All packs         | Comma-separated payload packs: `prompt_injection`, `jailbreak`, `sensitive_data_leak`. |
| `--concurrency`       | `-c`  | int    | `5`               | Maximum number of simultaneous async HTTP requests.                                    |
| `--delay`             | `-d`  | float  | `0.0`             | Pause delay in seconds between requests per worker.                                    |
| `--use-llm-judge`     |       | flag   | `False`           | Forces the local Ollama LLM Judge (`qwen2.5:0.5b`) to evaluate every payload.          |
| `--i-have-permission` |       | flag   | `False`           | Safety gate. Must be provided to confirm authorization to test the target.             |
| `--output-dir`        | `-o`  | path   | `scan_results`    | Directory where HTML, JSON, and log outputs are saved.                                 |

### Practical Examples

#### A. Basic Single-Turn Scan

```powershell
uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --i-have-permission
```

#### B. Scan Specific Payload Packs

For example, scan only Prompt Injection and Jailbreak payloads:

```powershell
uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --packs prompt_injection,jailbreak --i-have-permission
```

#### C. Scan a Target Requiring Authentication

```powershell
uv run scanner scan --url "https://api.example.com/v1/chat" --body-template '{"model":"gpt-4","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --auth-header "Authorization: Bearer my-secret-token" --i-have-permission
```

---

## 2. `scanner scan-multiturn` — Multi-Turn Attack Scan

Launches an automated Red-Team Attacker LLM that conducts multi-turn conversation attacks against the target model, escalating techniques across turns.

Techniques include:

* Rapport building
* Fictional framing
* Authority appeals
* Hypothetical escalation

### Syntax

```powershell
uv run scanner scan-multiturn --url <TARGET_URL> --body-template <JSON_TEMPLATE> [OPTIONS] --i-have-permission
```

### Options & Parameters

| Option                | Short | Type   | Default           | Description                                                        |
| --------------------- | ----- | ------ | ----------------- | ------------------------------------------------------------------ |
| `--url`               | `-u`  | string | Required          | Target API endpoint URL.                                           |
| `--body-template`     | `-b`  | string | Required          | JSON body template containing the `{{PROMPT}}` placeholder.        |
| `--response-field`    | `-r`  | string | `message.content` | Dotted-path key to extract model output text.                      |
| `--attacker-model`    |       | string | `qwen2.5:0.5b`    | Local Ollama model acting as the adversarial conversation driver.  |
| `--judge-model`       |       | string | `qwen2.5:0.5b`    | Local Ollama model acting as the Multi-Turn Judge evaluator.       |
| `--max-turns`         | `-m`  | int    | `4`               | Maximum conversation turns per scenario. Hard capped at 8.         |
| `--auth-header`       | `-a`  | string | None              | Custom HTTP headers, such as authentication tokens or API keys.    |
| `--packs`             | `-p`  | string | All packs         | Comma-separated multi-turn pack names, e.g. `multiturn_jailbreak`. |
| `--delay`             | `-d`  | float  | `0.5`             | Delay in seconds between turn exchanges.                           |
| `--i-have-permission` |       | flag   | `False`           | Safety gate. Required authorization confirmation.                  |
| `--output-dir`        | `-o`  | path   | `scan_results`    | Directory where HTML, JSON, and log outputs are saved.             |

### Practical Example

#### A. Basic Multi-Turn Scan — 4 Turns Maximum

```powershell
uv run scanner scan-multiturn --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --attacker-model qwen2.5:0.5b --max-turns 4 --i-have-permission
```

---

## 3. Auxiliary Utility Commands

### View Help

```powershell
uv run scanner --help
uv run scanner scan --help
uv run scanner scan-multiturn --help
```

### Run Automated Unit Tests

```powershell
uv run pytest
```

---

## 4. Generated Output Files

Whenever a scan completes, the following files are automatically created in the output directory:

```text
scan_results/
├── report.html
├── report.json
├── multiturn_report.json
└── scan.log
```

### `scan_results/report.html`

Interactive visual dashboard containing:

* Summary statistics cards
* Payload counts
* Vulnerabilities flagged
* Scan duration
* Circuit status
* OWASP tags:

  * `LLM01`
  * `LLM02`
  * `LLM06`
* Collapsible multi-turn conversation dialogue
* Exact turn where the target was compromised using `succeeded_at_turn`

### `scan_results/report.json`

Structured JSON report intended for CI/CD automation pipelines.

### `scan_results/multiturn_report.json`

Structured JSON report containing results from multi-turn adversarial scans.

### `scan_results/scan.log`

Detailed execution log containing:

* Request dispatches
* HTTP backoff retries such as `429` and `503`
* Circuit breaker events
* LLM judge evaluations
* Scan execution details
