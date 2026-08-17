uv run scanner scan-multiturn --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --attacker-model qwen2.5:0.5b --max-turns 4 --i-have-permission

uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{\"model\":\"qwen2.5:0.5b\",\"messages\":[{\"role\":\"user\",\"content\":\"{{PROMPT}}\"}]}' --response-field "message.content" --i-have-permission --packs 'jbb_harmful.yaml' --limit 20 --concurrency 2 --delay 0.3

uv run scanner scan --url "http://localhost:5000/api/chat" --body-template '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"{{PROMPT}}"}]}' --response-field "message.content" --i-have-permission

scanner dataset scan-behaviors --url http://localhost:5000/api/chat --response-field message.content --pack jbb_harmful.yaml --i-have-permission


py -m scanner.cli dataset eval-judge --csv dataset/judge-comparison.csv --sample-size 5 
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



1. scan — Single-Turn Security Scan
Executes single-turn security payload tests against a target **LLM** endpoint.

powershell
.venv\Scripts\python -m scanner.cli scan --url *[http://localhost:**5000**/api/chat*](http://localhost:**5000**/api/chat*) --body-template '{*prompt*:*{{**PROMPT**}}"}' --i-have-permission
Flags & Options:
Flag / Option	Short	Type	Default	Description
--url	-u	String	Required	Target **API** endpoint **URL**.
--body-template	-b	String	Required	**JSON** request body template containing {{**PROMPT**}} placeholder.
--i-have-permission		Flag	False	Required safety gate. Must be passed to authorize scanning.
--converters		String	None	Comma-separated converters to apply (e.g. base64,leetspeak,rot13,translation_zulu).
--use-llm-judge		Flag	False	Enforce local Ollama **LLM** judge for all evaluations.
--packs	-p	String	All	Comma-separated payload packs to run (e.g. prompt_injection,jailbreak).
--concurrency	-c	Int	5	Maximum simultaneous async **HTTP** requests.
--delay	-d	Float	0.0	Delay in seconds between requests per worker.
--response-field	-r	String	message.content	Dotted **JSON** path key to extract model response text.
--auth-header	-a	List	None	Custom headers (e.g. -a *Authorization: Bearer <key>*).
--output-dir	-o	Path	scan_results	Directory to save report.html, report.json, and scan.log.
Example with Converters & **LLM** Judge:
powershell
.venv\Scripts\python -m scanner.cli scan `
    --url *[http://localhost:**5000**/api/chat*](http://localhost:**5000**/api/chat*) `
    --body-template '{*prompt*:*{{**PROMPT**}}"}' `
    --converters base64,leetspeak,rot13,translation_zulu `
    --use-llm-judge `
    --i-have-permission
2. scan-multiturn — Multi-Turn Adversarial Scan
Executes multi-turn conversation attacks driven by an adversarial Attacker **LLM**.

powershell
.venv\Scripts\python -m scanner.cli scan-multiturn --url *[http://localhost:**5000**/api/chat*](http://localhost:**5000**/api/chat*) --body-template '{*prompt*:*{{**PROMPT**}}"}' --i-have-permission
Flags & Options:
Flag / Option	Short	Type	Default	Description
--url	-u	String	Required	Target **API** endpoint **URL**.
--body-template	-b	String	Required	**JSON** request body template with {{**PROMPT**}}.
--i-have-permission		Flag	False	Required safety gate.
--attacker-model		String	qwen2.5:0.5b	Local Ollama model driving red-team conversation turns.
--judge-model		String	qwen2.5:0.5b	Local Ollama model evaluating full transcript.
--max-turns	-m	Int	4	Maximum conversation turns per scenario (capped at 8).
--packs	-p	String	All	Comma-separated multi-turn payload scenario packs.
--delay	-d	Float	0.5	Delay in seconds between request turns.
--response-field	-r	String	message.content	Key path for target response.
--auth-header	-a	List	None	Custom **HTTP** headers.
--output-dir	-o	Path	scan_results	Directory to save multi-turn reports.
3. dataset import-behaviors — Import Dataset **CSV**
Converts harmful or benign behavior datasets (e.g. JailbreakBench) into **YAML** payload packs.

powershell
.venv\Scripts\python -m scanner.cli dataset import-behaviors --csv *dataset/harmful.csv* --output *scanner/payloads/jbb_harmful.yaml* --label harmful
Flags & Options:
Flag / Option	Type	Default	Description
--csv	Path	Required	Input **CSV** filepath containing behavior prompts.
--output	Path	Required	Destination **YAML** payload pack filepath.
--label	String	Required	Behavior label: harmful or benign.
--category	String	jailbreak	Category identifier assigned to imported payloads.
--owasp-id	String	**LLM01**	Mapped **OWASP** Top 10 category code.
4. dataset scan-behaviors — Scan Imported Dataset Pack
Runs security scan using imported dataset **YAML** packs and outputs success/false-positive metrics.

powershell
.venv\Scripts\python -m scanner.cli dataset scan-behaviors --url *[http://localhost:**5000**/api/chat*](http://localhost:**5000**/api/chat") --pack jbb_harmful.yaml --i-have-permission
Flags & Options:
Flag / Option	Short	Type	Default	Description
--url	-u	String	Required	Target **API** endpoint **URL**.
--pack	-p	String	Required	Payload pack filename or path (e.g., jbb_harmful.yaml).
--i-have-permission		Flag	False	Required safety gate.
--body-template	-b	String	{*prompt*: *{{**PROMPT**}}*}	**JSON** body template.
--use-llm-judge		Flag	False	Enforce **LLM** Judge evaluation.
--concurrency	-c	Int	5	Simultaneous requests limit.
--delay	-d	Float	0.0	Request delay.
--output-dir	-o	Path	scan_results	Output directory.
5. dataset eval-judge — Judge Accuracy Evaluation
Offline evaluation measuring heuristic and **LLM** judge accuracy/precision/recall against ground-truth human datasets.

powershell
.venv\Scripts\python -m scanner.cli dataset eval-judge --csv *dataset/judge-comparison.csv*
Flags & Options:
Flag / Option	Short	Type	Default	Description
--csv		Path	Required	Path to judge-comparison.csv ground truth dataset.
--sample-size	-s	Int	All	Optional random subset size for fast evaluation runs.
--judge-model		String	qwen2.5:0.5b	Ollama model name used for judging.
--ollama-url		String	[http://localhost:**11434**/api/chat](http://localhost:**11434**/api/chat)	Ollama **API** endpoint **URL**.
--timeout		Float	30.0	Timeout per **LLM** judge call in seconds.
--output-dir	-o	Path	scan_results	Directory to save judge_eval_report.json & **HTML** report.
💡 Converter Names Reference (--converters)
When using --converters with the scan command, you can combine any of the following:

base64 — Standard Base64 prompt encoding leetspeak — Character mapping (a->4, e->3, i->1, o->0, s->5, t->7) rot13 — **ROT13** cipher transformation translation_zulu — Translation to Zulu via local **LLM** translation_<lang> — Translation to any target language (e.g., translation_welsh, translation_yoruba)