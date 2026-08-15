# Development History & Changelog

This document summarizes the architectural evolution and implementation history of **LLM Sentinel Scanner**.

---

## 📜 Timeline of Development

### Phase 1: Core Foundation & Data Models
- Designed core dataclasses: `Payload`, `Finding`, `ScanResult`, `ConversationTurn`, `MultiTurnPayload`, and `MultiTurnFinding`.
- Built REST API adapter (`RESTAdapter`) using `httpx` to interface with generic LLM chat endpoints.
- Mapped OWASP Top 10 for LLM Applications security categories (`LLM01` Prompt Injection, `LLM02` Sensitive Data Leakage, `LLM06` Jailbreak).

### Phase 2: Async Scan Engine & Resilience
- Implemented high-throughput `ScanEngine` with Python `asyncio` concurrency semaphore.
- Added exponential retry backoff handling for HTTP 429 / 503 rate limits.
- Built automatic circuit breaker mechanism to halt scanning on target failure cascades.
- Standardized structured Python logging to `scan.log` and rich terminal progress reporting.

### Phase 3: Multi-Turn Adversarial Red-Teaming
- Developed `AttackerLLM` driver module to dynamically orchestrate multi-turn dialogue escalation attacks.
- Built `judge_conversation()` evaluator to assess full turn-by-turn conversation transcripts.
- Added `scan-multiturn` CLI command for multi-turn red-teaming evaluation.

### Phase 4: Benchmark Dataset Integration
- Added JailbreakBench dataset import tools (`dataset import-behaviors`) for converting raw CSV datasets to YAML payload packs (`jbb_harmful.yaml`, `jbb_benign.yaml`).
- Created `dataset scan-behaviors` command to measure jailbreak success and false-positive rates.
- Implemented `dataset eval-judge` to evaluate judge accuracy, precision, recall, and F1 score against human ground-truth datasets.

### Phase 5: LLM Judge Optimization & Rubric Alignment
- Refactored `LLMJudge` with strict rubric prompt alignment, JSON markdown-fence stripping, retry logic, and fallback heuristics.
- Standardized error logging so LLM judge fallback events (`heuristic_fallback_llm_error`) are visibly highlighted.

### Phase 6: Payload Prompt Converters
- Added `scanner/converters/` module featuring `Base64Converter`, `LeetspeakConverter`, `Rot13Converter`, and `TranslationConverter` (local LLM translation).
- Extended single-turn engine with `run_scan_with_converters()` ensuring plain-text baseline comparison for every converted prompt.
- Added CLI `--converters` flag and Jinja2 HTML report comparison tables with `⚡ BYPASS DETECTED` visual alerts.

### Phase 7: Consolidation & Refactoring
- Consolidated all Ollama HTTP API interactions into a single shared helper `scanner/common/ollama_client.py`.
- Reorganized payload library into `handwritten/` and `jbb_derived/` subdirectories with recursive loader support (`rglob`).
- Standardized CLI options with payload execution limit (`--limit` / `-l`).
- Complete documentation audit and unit test suite verification.
