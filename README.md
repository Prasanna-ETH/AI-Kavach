# 🛡️ KAVACH-PoF — Evidence-Gated Autonomous Cyber Reasoning System (CRS)

> **Theme:** *Kavach means Shield: Defensive by Design*  
> **Challenge:** **AI Kavach Cyber Challenge 2026** (Defense & National Security AI Innovation)  
> **Core Thesis:** **"PATCH ACCEPTED ≠ VULNERABILITY FIXED"** — *Fixing the crash is not the same as fixing the vulnerability.*

---

## 📌 Executive Summary

**KAVACH-PoF** is an autonomous, lightweight **Cyber Reasoning System (CRS)** designed to secure AI models, LLM endpoints, autonomous agents, and enterprise software infrastructure against adversarial threats.

By lacing Large Language Models with **high-entropy fuzzers**, **static AST & prompt analyzers**, **a 3-tier intelligent vulnerability judge**, an **autonomous patch generator**, and a **dynamic regression test harness**, KAVACH-PoF autonomously executes a complete 5-stage defensive lifecycle:

$$\text{DISCOVER} \longrightarrow \text{UNDERSTAND} \longrightarrow \text{REPAIR} \longrightarrow \text{VERIFY} \longrightarrow \text{PROVE}$$

Unlike traditional automated patchers that consider a fix successful if code compiles or stops crashing, **KAVACH-PoF requires verifiable evidence** that the root cause was repaired, zero functional regression was introduced, and the patch survives targeted adversarial re-fuzzing.

---

## 🏛️ System Architecture & Workflow

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        KAVACH-PoF 5-STAGE AUTONOMOUS CYBER REASONING PIPELINE                         │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                        │
│  [1. DISCOVER] ─────────► [2. UNDERSTAND] ────────► [3. REPAIR] ────────► [4. VERIFY] ──────► [5. PROVE]  │
│   • Fuzz Seed Generator    • AST Prompt Analyzer    • LLM Patch Gen    • Regression Test  • Proof-of-Fix │
│   • 3,378 OWASP Vectors    • Root-Cause Mapper      • Constraint Inject • Re-Fuzzing Engine • Evidence Trail│
│   • Playwright DOM Probe   • DLP & Secret Scanner   • AST Rewriter     • 100% Retain Check • SARIF / PoF  │
│                                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### The 5-Stage Autonomous Loop

1. **STAGE 1: DISCOVER (Autonomous Fuzzing & Scanning)**
   - Executes multi-modal fuzzing probes (Base64, ROT13, Story Mode, Composite Obfuscation) across REST endpoints and headless Chromium Playwright browser widgets.
   - Maps vulnerabilities to **OWASP Top 10 for LLMs** (`LLM01` Prompt Injection & Jailbreaks, `LLM02` Sensitive Data Disclosure, `LLM07` System Prompt Exfiltration, `LLM10` Insecure Output Exfiltration).

2. **STAGE 2: UNDERSTAND (Root Cause & Static AST Analysis)**
   - Runs static AST scanning and prompt inspection to isolate whether a vulnerability stems from hardcoded secrets, over-privileged function tools, missing refusal directives, or un-sanitized output tags.

3. **STAGE 3: REPAIR (Autonomous Patch Generation)**
   - Synthesizes a targeted software patch and hardened guardrail constraint set designed specifically for the identified root cause.

4. **STAGE 4: VERIFY (Regression Harness & Re-Fuzzing)**
   - Executes pre-patch vs. post-patch regression tests against benign business queries to ensure 100% functional retention with zero performance regression.
   - Subject the patched software to targeted adversarial re-fuzzing.

5. **STAGE 5: PROVE (Evidence Artifact Generation)**
   - Generates the official **Proof-of-Fix (PoF)** cryptographic evidence artifact containing the full verification trail (`proof_of_fix_artifact.json` and SARIF 2.1.0 reports).

---

## 🌟 Salient Features & Unique Innovations (USP)

### 1. 🛡️ Evidence-Gated Verification ("Patch Accepted ≠ Vulnerability Fixed")
Traditional automated patchers trust a patch if it compiles and passes basic unit tests. KAVACH-PoF enforces a 7-tier verification trail before issuing a **Proof-of-Fix**:
1. Vulnerability reproduction confirmed pre-patch.
2. Root cause explicitly isolated.
3. Patch correctly addresses root cause.
4. Vulnerability no longer reproduces under original attack vector.
5. Intended system functionality 100% retained.
6. Zero side-effect regression introduced.
7. Patched target survives aggressive re-fuzzing.

### 2. ⚡ Lightweight & Resource-Efficient Edge Architecture
Designed for resource-constrained defense environments and Armed Forces edge infrastructure:
- **Tier 0 Pre-filtering ($<0.01\text{ ms}$)**: Pre-compiled regex matching 150+ refusal templates (0 LLM tokens consumed).
- **Tier 1 DLP & Secret Engine ($<0.5\text{ ms}$)**: Built-in Gitleaks secret rules and Presidio PII pattern matching.
- **Tier 2 Calibrated Likert Judge**: Local neural evaluation (`qwen2.5:3b`, `llama3.1:8b`) with zero cloud dependencies.

### 3. 🖥️ Live Operational Command Center (Web GUI)
FastAPI backend + React/Vite/Tailwind frontend displaying real-time target health, live SSE attack telemetry, graduated 0-to-4 Likert score distributions, and 1-click retest capabilities.

### 4. 🔗 CI/CD & Defense System Integration Library (`/library`)
Includes a standalone Python SDK library, CLI build-break hook scripts (`python -m library.cli_hook`), pre-commit hooks, and GitHub Action workflows exporting SARIF 2.1.0, JUnit XML, and Markdown summaries.

---

## 💻 Tech Stack

- **Core Engine & CRS**: Python 3.10+, Asyncio, Pydantic, PyYAML, Typer
- **Fuzzing & Transport**: HTTPx (Async REST POST/GET), Playwright (Headless Chromium Browser DOM Delta-Diffing)
- **Neural Reasoning & LLM**: Ollama (`qwen2.5:3b`, `llama3.1:8b`), Graduated Likert-Scale Rubric Engine (0 to 4)
- **Backend API**: FastAPI, Uvicorn, Server-Sent Events (SSE)
- **Frontend Dashboard**: React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, Recharts
- **CI/CD & Reporting**: SARIF 2.1.0, JUnit XML, Markdown, JSON Artifacts

---

## 🚀 Quick Start Guide

### Option 1: Run Autonomous KAVACH-PoF Cyber Reasoning Pipeline (CLI)

Run the autonomous 5-stage CRS loop against any software endpoint:

```bash
# Run autonomous Discover -> Understand -> Repair -> Verify -> Prove loop
python -m crs.runner --target-url "http://localhost:5000/api/chat"
```

Output:
```text
======================================================================
 [KAVACH-PoF] EVIDENCE-GATED CYBER REASONING SYSTEM (CRS)
              Theme: Defensive by Design | AI Kavach Challenge 2026
======================================================================
[*] Target Endpoint: http://localhost:5000/api/chat
[*] Core Thesis: PATCH ACCEPTED != VULNERABILITY FIXED

[STAGE 1: DISCOVER] Launching Autonomous Fuzzer & Vulnerability Probe...
[+] Discovered vulnerable attack vector: 'OVERRIDE SYSTEM DIRECTIVE'

[STAGE 2: UNDERSTAND] Executing Static AST & Prompt Analysis...
[+] Root cause identified: Hardcoded Secrets in System Prompt

[STAGE 3: REPAIR] Autonomous LLM Repair Engine Generating Patch...
[+] Synthesized Patch: PATCH-2026-001 (Guardrail Sanitization)

[STAGE 4: VERIFY] Executing Regression Test Harness & Re-Fuzzing...
[+] Regression Checks Passed: 3/3 (100% Functionality Retained)

[STAGE 5: PROVE] Generating Proof-of-Fix (PoF) Evidence Artifact...

[OK] PROOF-OF-FIX VERIFIED!
[OK] Artifact exported to: proof_of_fix_artifact.json
======================================================================
```

---

### Option 2: Run the Web Dashboard & Vulnerable Target App

#### 1. Start the Vulnerable Target Application
```bash
# Simulates an enterprise banking AI endpoint (Apex Wealth AI)
uv run targets/vulnerable_ollama_wrapper.py
```
* Target Web UI: http://localhost:5000/chat  
* Target API: http://localhost:5000/api/chat  

#### 2. Start the FastAPI Backend Server
```bash
uv run uvicorn backend.api.main:app --reload --port 8000
```
* API Swagger Docs: http://localhost:8000/docs

#### 3. Start the React Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
* Dashboard URL: http://localhost:5173

---

### Option 3: Run Standalone Library / CI Integration (`/library`)

Run security audit as a python library or CI/CD gate:

```python
from library import scan_target

# Execute security audit & generate SARIF/JUnit reports
report = scan_target("http://localhost:5000/api/chat", fail_on="HIGH")
report.save_sarif("results.sarif")
report.save_junit_xml("results.xml")

print(report.summary())
```

---

## 📑 Slide Deck & Presentation Structure (5-Slide Proposal)

Our submission for the initial round is structured as a technical story:

1. **Slide 1 — Problem Statement & Solution Overview**
   - Problem: AI & LLM software in defense infrastructure faces stealthy prompt injections, data exfiltration, and fragile automated patches.
   - Core Idea: KAVACH-PoF — evidence-gated CRS that verifies root causes and proves patch durability.
2. **Slide 2 — Detailed Methodology & 5-Stage Workflow**
   - Step-by-step breakdown: Discover $\rightarrow$ Understand $\rightarrow$ Repair $\rightarrow$ Verify $\rightarrow$ Prove.
3. **Slide 3 — Technology Stack & Architecture Block Diagram**
   - System flowchart connecting Fuzzer, AST Analyzer, Likert Judge, Regression Harness, and Proof-of-Fix Verifier.
4. **Slide 4 — Salient Features & Uniqueness (USP)**
   - Proof-of-Fix evidence trail, sub-millisecond edge pre-filtering, 0-4 Likert scoring, multi-modal REST & Browser support.
5. **Slide 5 — Deliverables & Proof of Concept**
   - Operational prototype, verifiable JSON evidence artifacts, SARIF compliance reports, and live web operational dashboard.

---

## 📄 License & Attribution

Developed for the **AI Kavach Cyber Challenge 2026**. Open source under the MIT License.
