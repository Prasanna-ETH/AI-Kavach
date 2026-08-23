import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Play, 
  Sliders, 
  Check, 
  Globe, 
  Server, 
  CheckCircle2, 
  XCircle, 
  HelpCircle, 
  ChevronDown, 
  ChevronRight, 
  Lock,
  Sparkles,
  KeyRound,
  Cookie,
  ShieldCheck
} from 'lucide-react';
import { api } from '../api/client';
import type { 
  BrowserTestSelectorsResponse, 
  PayloadPackInfo, 
  ScanMode, 
  ScanRequest, 
  TargetType 
} from '../types';
import { SectionHeader, OwaspBadge, ErrorBanner, LoadingState, Spinner } from '../components';

const AVAILABLE_CONVERTERS = [
  { id: 'base64', name: 'Base64 Encoding', desc: 'Encodes payload to standard base64 string' },
  { id: 'leetspeak', name: 'Leetspeak Obfuscation', desc: 'Substitutes alphanumeric character lookalikes (e.g. E->3, A->4)' },
  { id: 'rot13', name: 'ROT13 Cipher', desc: 'Applies Caesar 13-shift cipher to bypass basic keyword filters' },
  { id: 'roleplay', name: 'Adversarial Roleplay Wrapper', desc: 'Wraps attack instructions inside fictional narrative boundaries' },
  { id: 'translation_zulu', name: 'Low-Resource Translation (Zulu)', desc: 'Translates attack into low-resource language to test multilingual guardrails' },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const requestedPack = searchParams.get('pack');

  // Target Type State: 'rest' | 'browser'
  const [targetType, setTargetType] = useState<TargetType>('rest');

  // Common / REST State
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000/chat');
  const [bodyTemplate, setBodyTemplate] = useState('{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}');
  const [responseField, setResponseField] = useState('message.content');
  const [authHeader, setAuthHeader] = useState('');
  const [authType, setAuthType] = useState<'bearer' | 'cookie' | 'apikey' | 'custom' | ''>('');

  // Browser Target State
  const [browserUrl, setBrowserUrl] = useState('http://localhost:3000');
  const [inputSelector, setInputSelector] = useState("textarea, input[name='message'], input#chat-input");
  const [sendButtonSelector, setSendButtonSelector] = useState("button[type='submit'], button#send");
  const [responseSelector, setResponseSelector] = useState(".message.assistant, .bot-message, #chat-response");
  const [waitForResponseTimeout, setWaitForResponseTimeout] = useState<number>(10);

  // Browser Login Flow (Optional)
  const [showLoginSection, setShowLoginSection] = useState(false);
  const [usernameSelector, setUsernameSelector] = useState('');
  const [usernameValue, setUsernameValue] = useState('');
  const [passwordSelector, setPasswordSelector] = useState('');
  const [passwordValue, setPasswordValue] = useState('');
  const [loginButtonSelector, setLoginButtonSelector] = useState('');

  // Selector Validation State
  const [testingSelectors, setTestingSelectors] = useState(false);
  const [testResult, setTestResult] = useState<BrowserTestSelectorsResponse | null>(null);

  // Attack Strategy & Judge State
  const [scanMode, setScanMode] = useState<ScanMode>('single');
  const [maxTurns, setMaxTurns] = useState<number>(4);
  const [selectedConverters, setSelectedConverters] = useState<string[]>(['base64', 'leetspeak']);
  
  const [useLlmJudge, setUseLlmJudge] = useState(true);
  const [judgeModel, setJudgeModel] = useState('qwen2.5:3b');
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434/api/chat');
  
  const [concurrency, setConcurrency] = useState(5);
  const [delay, setDelay] = useState(0.0);
  const [limit, setLimit] = useState<string>('50');

  // Payload Packs Data
  const [packs, setPacks] = useState<PayloadPackInfo[]>([]);
  const [selectedPacks, setSelectedPacks] = useState<string[]>([]);
  const [loadingPacks, setLoadingPacks] = useState(true);

  // Submission State
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadPacks() {
      try {
        setLoadingPacks(true);
        const data = await api.getPayloadPacks();
        setPacks(data);

        if (requestedPack && data.some(p => p.name === requestedPack)) {
          setSelectedPacks([requestedPack]);
        } else {
          const defaultSelected = data
            .filter(p => p.name.includes('quick_50') || p.name.includes('llm01') || p.name.includes('llm02'))
            .slice(0, 3)
            .map(p => p.name);
          setSelectedPacks(defaultSelected.length > 0 ? defaultSelected : data.slice(0, 2).map(p => p.name));
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to fetch payload packs');
      } finally {
        setLoadingPacks(false);
      }
    }
    loadPacks();
  }, [requestedPack]);

  const togglePack = (name: string) => {
    setSelectedPacks(prev => 
      prev.includes(name) ? prev.filter(p => p !== name) : [...prev, name]
    );
  };

  const selectAllPacks = () => {
    setSelectedPacks(packs.map(p => p.name));
  };

  const clearAllPacks = () => {
    setSelectedPacks([]);
  };

  const toggleConverter = (id: string) => {
    setSelectedConverters(prev => 
      prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]
    );
  };

  const handleTestSelectors = async () => {
    const url = browserUrl.trim();
    if (!url) {
      setError('Target Page URL is required to test selectors');
      return;
    }
    if (!inputSelector.trim()) {
      setError('Chat Input Selector is required');
      return;
    }

    try {
      setTestingSelectors(true);
      setError(null);
      setTestResult(null);

      const loginConfig = (usernameSelector.trim() && passwordSelector.trim()) ? {
        username_selector: usernameSelector.trim(),
        username_value: usernameValue,
        password_selector: passwordSelector.trim(),
        password_value: passwordValue,
        login_button_selector: loginButtonSelector.trim(),
      } : undefined;

      const res = await api.testBrowserSelectors({
        target_url: url,
        input_selector: inputSelector.trim(),
        send_button_selector: sendButtonSelector.trim() || undefined,
        response_selector: responseSelector.trim() || undefined,
        wait_for_response_timeout: Number(waitForResponseTimeout),
        login_config: loginConfig,
        auth_header: authHeader.trim() || undefined,
      });
      setTestResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Selector test request failed');
    } finally {
      setTestingSelectors(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const effectiveUrl = targetType === 'browser' ? browserUrl.trim() : targetUrl.trim();
    if (!effectiveUrl) {
      setError('Target URL is required');
      return;
    }
    if (selectedPacks.length === 0) {
      setError('Please select at least one payload pack');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);

      const loginConfig = (targetType === 'browser' && usernameSelector.trim() && passwordSelector.trim()) ? {
        username_selector: usernameSelector.trim(),
        username_value: usernameValue,
        password_selector: passwordSelector.trim(),
        password_value: passwordValue,
        login_button_selector: loginButtonSelector.trim(),
      } : undefined;

      const requestPayload: ScanRequest = {
        target_type: targetType,
        target_url: effectiveUrl,
        // REST fields
        body_template: targetType === 'rest' ? (bodyTemplate.trim() || undefined) : undefined,
        response_field: targetType === 'rest' ? responseField.trim() : undefined,
        // Auth header works for BOTH REST and Browser targets
        auth_header: authHeader.trim() || undefined,
        // Browser fields
        input_selector: targetType === 'browser' ? inputSelector.trim() : undefined,
        send_button_selector: targetType === 'browser' ? sendButtonSelector.trim() : undefined,
        response_selector: targetType === 'browser' ? responseSelector.trim() : undefined,
        wait_for_response_timeout: targetType === 'browser' ? Number(waitForResponseTimeout) : undefined,
        login_config: loginConfig,
        // Common attack options
        packs: selectedPacks,
        scan_mode: scanMode,
        max_turns: maxTurns,
        converters: scanMode === 'converter' ? selectedConverters : undefined,
        use_llm_judge: useLlmJudge,
        judge_model: judgeModel.trim(),
        ollama_url: ollamaUrl.trim(),
        delay: Number(delay),
        concurrency: targetType === 'browser' ? 1 : Number(concurrency),
        limit: limit.trim() ? Number(limit) : undefined,
      };

      const res = await api.createScan(requestPayload);
      navigate(`/scan/live?id=${res.scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to initiate scan execution');
      setIsSubmitting(false);
    }
  };

  const groupedPacks = packs.reduce((acc, pack) => {
    const key = pack.category || 'General';
    if (!acc[key]) acc[key] = [];
    acc[key].push(pack);
    return acc;
  }, {} as Record<string, PayloadPackInfo[]>);

  if (loadingPacks) {
    return <LoadingState message="Loading available attack vectors and payload library..." />;
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      <SectionHeader
        title="Configure New Vulnerability Scan"
        subtitle="Set endpoint parameters, select attack vectors, and customize evaluation judges"
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* 1. Target Endpoint Configuration with Target Type Branching */}
        <div className="card p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-navy-800 pb-4">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Target Endpoint Configuration</h2>
              <p className="text-xs text-slate-400 mt-0.5">Select whether you are auditing a REST API endpoint or a browser-based chat widget</p>
            </div>

            {/* Target Type Selector Pills */}
            <div className="flex bg-navy-950 p-1 rounded-lg border border-navy-800">
              <button
                type="button"
                onClick={() => setTargetType('rest')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  targetType === 'rest'
                    ? 'bg-teal-500 text-navy-950 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Server size={14} /> REST API Endpoint
              </button>
              <button
                type="button"
                onClick={() => setTargetType('browser')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  targetType === 'browser'
                    ? 'bg-teal-500 text-navy-950 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Globe size={14} /> Browser Widget (Playwright)
              </button>
            </div>
          </div>

          {/* BRANCH A: REST API Target (EXISTING UNCHANGED) */}
          {targetType === 'rest' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Target Endpoint URL <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  className="input-base font-mono text-xs"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  placeholder="http://localhost:5000/chat or https://api.openai.com/v1/chat/completions"
                  required
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Accepts REST endpoints. Supports query parameters with <code className="text-teal-400">{'{{PROMPT}}'}</code> or JSON POST requests.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Response Extraction Path (Dotted Notation)
                </label>
                <input
                  type="text"
                  className="input-base font-mono text-xs"
                  value={responseField}
                  onChange={e => setResponseField(e.target.value)}
                  placeholder="message.content or choices.0.message.content"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Auto-detects standard LLM schemas (Ollama, OpenAI, Anthropic, Gemini).
                </p>
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  JSON Request Body Template
                </label>
                <textarea
                  className="input-base font-mono text-xs h-20"
                  value={bodyTemplate}
                  onChange={e => setBodyTemplate(e.target.value)}
                  placeholder='{"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "{{PROMPT}}"}]}'
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Use <code className="text-teal-400">{'{{PROMPT}}'}</code> as the substitution placeholder for security attack payloads.
                </p>
              </div>
            </div>
          )}

          {/* BRANCH B: Browser Widget (Playwright-driven) */}
          {targetType === 'browser' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Target Web Page URL <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={browserUrl}
                    onChange={e => setBrowserUrl(e.target.value)}
                    placeholder="http://localhost:3000 or https://chat.targetapp.internal"
                    required
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Playwright will launch headless Chromium, navigate to this page, and interact with the chat elements.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Chat Input Selector (CSS) <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={inputSelector}
                    onChange={e => setInputSelector(e.target.value)}
                    placeholder="textarea, input[name='message'], input#chat-input"
                    required
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    CSS selector for the text input or textarea where attack prompts are typed.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Send Button Selector (CSS)
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={sendButtonSelector}
                    onChange={e => setSendButtonSelector(e.target.value)}
                    placeholder="button[type='submit'], button#send, button.send"
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Button clicked to submit prompt. Falls back to pressing Enter on the input if not found.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Response Element Selector (CSS)
                  </label>
                  <input
                    type="text"
                    className="input-base font-mono text-xs"
                    value={responseSelector}
                    onChange={e => setResponseSelector(e.target.value)}
                    placeholder=".message.assistant, .bot-message, div[data-role='assistant']"
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Selector for the assistant's message container. Uses snapshot delta-diffing as fallback.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                    Response Wait Timeout (Seconds)
                  </label>
                  <input
                    type="number"
                    min="2"
                    max="60"
                    className="input-base font-mono text-xs"
                    value={waitForResponseTimeout}
                    onChange={e => setWaitForResponseTimeout(Number(e.target.value))}
                  />
                  <p className="text-[11px] text-slate-500 mt-1">
                    Max time to wait for the assistant's reply to render (default 10s).
                  </p>
                </div>
              </div>

              {/* Collapsible: Advanced Login Flow */}
              <div className="border border-navy-800 rounded-lg overflow-hidden bg-navy-950/40">
                <div 
                  className="p-3 bg-navy-900/60 cursor-pointer flex items-center justify-between text-xs font-semibold text-slate-300 select-none hover:text-white"
                  onClick={() => setShowLoginSection(!showLoginSection)}
                >
                  <div className="flex items-center gap-2">
                    <Lock size={13} className="text-teal-400" />
                    <span>Advanced: Automated Login Flow (Optional)</span>
                  </div>
                  {showLoginSection ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </div>

                {showLoginSection && (
                  <div className="p-4 border-t border-navy-800 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div>
                      <label className="block font-semibold text-slate-300 mb-1">Username Input Selector</label>
                      <input
                        type="text"
                        className="input-base font-mono text-xs"
                        value={usernameSelector}
                        onChange={e => setUsernameSelector(e.target.value)}
                        placeholder="input[name='username'], #user-email"
                      />
                    </div>

                    <div>
                      <label className="block font-semibold text-slate-300 mb-1">Username / Email Value</label>
                      <input
                        type="text"
                        className="input-base text-xs"
                        value={usernameValue}
                        onChange={e => setUsernameValue(e.target.value)}
                        placeholder="admin@internal.corp"
                      />
                    </div>

                    <div>
                      <label className="block font-semibold text-slate-300 mb-1">Password Input Selector</label>
                      <input
                        type="text"
                        className="input-base font-mono text-xs"
                        value={passwordSelector}
                        onChange={e => setPasswordSelector(e.target.value)}
                        placeholder="input[name='password'], #user-pass"
                      />
                    </div>

                    <div>
                      <label className="block font-semibold text-slate-300 mb-1">Password Value</label>
                      <input
                        type="password"
                        className="input-base text-xs"
                        value={passwordValue}
                        onChange={e => setPasswordValue(e.target.value)}
                        placeholder="••••••••"
                      />
                    </div>

                    <div className="md:col-span-2">
                      <label className="block font-semibold text-slate-300 mb-1">Login Button Selector</label>
                      <input
                        type="text"
                        className="input-base font-mono text-xs"
                        value={loginButtonSelector}
                        onChange={e => setLoginButtonSelector(e.target.value)}
                        placeholder="button[type='submit'], #login-btn"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Selector Health-Check Test Button & Results */}
              <div className="pt-2">
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={handleTestSelectors}
                    disabled={testingSelectors || !browserUrl.trim()}
                    className="btn-secondary text-xs flex items-center gap-1.5 px-4 py-2 border-teal-500/40 text-teal-400 hover:border-teal-500"
                  >
                    {testingSelectors ? (
                      <>
                        <Spinner size={13} /> Validating Selectors on Page...
                      </>
                    ) : (
                      <>
                        <HelpCircle size={13} /> Test Selectors (Health Check)
                      </>
                    )}
                  </button>
                  <span className="text-[11px] text-slate-500">
                    Fails fast before starting a scan by verifying input/button elements exist on the page.
                  </span>
                </div>

                {/* Test Results Display */}
                {testResult && (
                  <div className={`mt-3 p-4 rounded-lg border text-xs space-y-2.5 ${
                    testResult.ok 
                      ? 'bg-emerald-950/30 border-emerald-800/50' 
                      : 'bg-red-950/30 border-red-800/50'
                  }`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-semibold">
                        {testResult.ok ? (
                          <span className="text-emerald-400 flex items-center gap-1.5">
                            <CheckCircle2 size={16} /> Selectors Verified Successfully
                          </span>
                        ) : (
                          <span className="text-red-400 flex items-center gap-1.5">
                            <XCircle size={16} /> Selector Validation Failed
                          </span>
                        )}
                      </div>
                      <span className="font-mono text-[10px] text-slate-400">{testResult.url}</span>
                    </div>

                    {testResult.error && (
                      <p className="text-red-300 text-xs font-mono bg-red-950/60 p-2 rounded border border-red-900/50">
                        {testResult.error}
                      </p>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2 pt-1 font-mono text-[11px]">
                      {Object.entries(testResult.selectors).map(([key, item]) => (
                        <div key={key} className="p-2 bg-navy-950/80 rounded border border-navy-800 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-400">{key}:</span>
                            {item.found ? (
                              <span className="text-emerald-400 font-bold">FOUND</span>
                            ) : (
                              <span className="text-red-400 font-bold">MISSING</span>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-500 truncate" title={item.selector}>
                            {item.selector}
                          </div>
                          {item.note && <div className="text-[10px] text-teal-400/80">{item.note}</div>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Authentication & Custom Headers Card */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-navy-800 pb-3">
            <KeyRound size={16} className="text-teal-400" />
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Authentication &amp; Custom Headers</h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Inject Bearer tokens, session cookies, API keys, or any HTTP header — applies to <span className="text-teal-400 font-semibold">both REST and Browser</span> targets.
              </p>
            </div>
          </div>

          {/* Quick-fill preset buttons */}
          <div className="space-y-3">
            <p className="text-[11px] text-slate-400 font-medium uppercase tracking-wider">Quick Presets</p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => { setAuthType('bearer'); if (!authHeader.startsWith('Bearer ')) setAuthHeader('Bearer '); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
                  authType === 'bearer' ? 'bg-teal-500/15 border-teal-500 text-teal-300' : 'border-navy-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                <KeyRound size={12} /> Bearer Token
              </button>
              <button
                type="button"
                onClick={() => { setAuthType('cookie'); if (!authHeader.startsWith('Cookie:')) setAuthHeader('Cookie: session_id='); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
                  authType === 'cookie' ? 'bg-teal-500/15 border-teal-500 text-teal-300' : 'border-navy-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                <Cookie size={12} /> Cookie / Session ID
              </button>
              <button
                type="button"
                onClick={() => { setAuthType('apikey'); if (!authHeader.startsWith('X-API-Key:')) setAuthHeader('X-API-Key: '); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
                  authType === 'apikey' ? 'bg-teal-500/15 border-teal-500 text-teal-300' : 'border-navy-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                <ShieldCheck size={12} /> API Key Header
              </button>
              <button
                type="button"
                onClick={() => { setAuthType('custom'); setAuthHeader(''); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
                  authType === 'custom' ? 'bg-teal-500/15 border-teal-500 text-teal-300' : 'border-navy-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                Custom Header
              </button>
              {authHeader && (
                <button
                  type="button"
                  onClick={() => { setAuthType(''); setAuthHeader(''); }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border border-red-500/40 text-red-400 hover:border-red-500 hover:text-red-300 transition-all"
                >
                  <XCircle size={12} /> Clear
                </button>
              )}
            </div>

            {/* Header Input */}
            <div>
              <input
                type="text"
                id="auth-header-input"
                className="input-base font-mono text-xs"
                value={authHeader}
                onChange={e => { setAuthHeader(e.target.value); setAuthType('custom'); }}
                placeholder={
                  authType === 'bearer' ? 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' :
                  authType === 'cookie' ? 'Cookie: session_id=abc123xyz; token=def456' :
                  authType === 'apikey' ? 'X-API-Key: your-api-key-here' :
                  'Bearer <token>  or  Cookie: session_id=<id>  or  X-API-Key: <key>'
                }
              />
            </div>

            {/* Live preview of what will be sent */}
            {authHeader.trim() && (
              <div className="flex items-start gap-2 bg-navy-950/60 border border-navy-700 rounded-lg px-3 py-2.5">
                <CheckCircle2 size={13} className="text-emerald-400 mt-0.5 shrink-0" />
                <div className="text-[11px] font-mono">
                  <span className="text-slate-400">Header being sent → </span>
                  {authHeader.includes(':') ? (
                    <>
                      <span className="text-yellow-300">{authHeader.split(':')[0].trim()}</span>
                      <span className="text-slate-400">: </span>
                      <span className="text-teal-300">{authHeader.split(':').slice(1).join(':').trim()}</span>
                    </>
                  ) : (
                    <>
                      <span className="text-yellow-300">Authorization</span>
                      <span className="text-slate-400">: </span>
                      <span className="text-teal-300">{authHeader.trim()}</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Format tips */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-slate-500">
              <div className="flex items-center gap-1.5">
                <span className="text-teal-500">→</span>
                <span><code className="text-slate-300">Bearer sk-xxxx</code> → sets <code className="text-slate-300">Authorization: Bearer sk-xxxx</code></span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-teal-500">→</span>
                <span><code className="text-slate-300">Cookie: sid=abc</code> → sets <code className="text-slate-300">Cookie: sid=abc</code></span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-teal-500">→</span>
                <span><code className="text-slate-300">X-API-Key: key</code> → sets <code className="text-slate-300">X-API-Key: key</code></span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-teal-500">→</span>
                <span>Any <code className="text-slate-300">Header-Name: value</code> format is supported</span>
              </div>
            </div>
          </div>
        </div>

        {/* 2. Attack Mode Selection */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-navy-800 pb-3">
            <Sliders size={18} className="text-teal-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Attack Mode & Execution Strategy</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div 
              onClick={() => setScanMode('single')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanMode === 'single'
                  ? 'border-teal-500 bg-teal-500/10'
                  : 'border-navy-800 bg-navy-950/40 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-white">Single-Turn Direct</span>
                <span className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center ${scanMode === 'single' ? 'border-teal-400 bg-teal-400' : 'border-slate-600'}`}>
                  {scanMode === 'single' && <span className="w-1.5 h-1.5 rounded-full bg-navy-950" />}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Direct single-turn attack payloads evaluated with heuristics and calibrated LLM scoring.
              </p>
            </div>

            <div 
              onClick={() => setScanMode('multiturn')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanMode === 'multiturn'
                  ? 'border-teal-500 bg-teal-500/10'
                  : 'border-navy-800 bg-navy-950/40 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-white">Multi-Turn Adversarial</span>
                <span className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center ${scanMode === 'multiturn' ? 'border-teal-400 bg-teal-400' : 'border-slate-600'}`}>
                  {scanMode === 'multiturn' && <span className="w-1.5 h-1.5 rounded-full bg-navy-950" />}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Orchestrates dynamic multi-step adversarial dialogs using an automated red-team LLM attacker.
              </p>
            </div>

            <div 
              onClick={() => setScanMode('converter')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanMode === 'converter'
                  ? 'border-teal-500 bg-teal-500/10'
                  : 'border-navy-800 bg-navy-950/40 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-white">With Payload Converters</span>
                <span className={`w-3.5 h-3.5 rounded-full border flex items-center justify-center ${scanMode === 'converter' ? 'border-teal-400 bg-teal-400' : 'border-slate-600'}`}>
                  {scanMode === 'converter' && <span className="w-1.5 h-1.5 rounded-full bg-navy-950" />}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Transforms payloads (Base64, Leetspeak, ROT13, etc.) alongside plain-text baselines to detect filter bypasses.
              </p>
            </div>
          </div>

          {scanMode === 'multiturn' && (
            <div className="p-4 bg-navy-950/60 rounded-lg border border-navy-800 space-y-3 mt-4">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-200">
                  Maximum Conversation Turns per Scenario: <span className="text-teal-400 font-mono text-sm">{maxTurns}</span>
                </label>
                <span className="text-[10px] text-slate-500">Engine hard safety limit: 8 turns</span>
              </div>
              <input
                type="range"
                min="2"
                max="8"
                step="1"
                value={maxTurns}
                onChange={e => setMaxTurns(Number(e.target.value))}
                className="w-full accent-teal-500 cursor-pointer"
              />
            </div>
          )}

          {scanMode === 'converter' && (
            <div className="p-4 bg-navy-950/60 rounded-lg border border-navy-800 space-y-3 mt-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">Select Obfuscation & Transformation Converters</span>
                <span className="text-[10px] text-teal-400 bg-teal-950/60 px-2 py-0.5 rounded border border-teal-800/40">
                  Plain-text baseline always included
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {AVAILABLE_CONVERTERS.map(conv => {
                  const isChecked = selectedConverters.includes(conv.id);
                  return (
                    <div
                      key={conv.id}
                      onClick={() => toggleConverter(conv.id)}
                      className={`p-2.5 rounded border flex items-start gap-2.5 cursor-pointer text-xs transition-colors ${
                        isChecked 
                          ? 'border-teal-500/60 bg-teal-950/20 text-white' 
                          : 'border-navy-800 bg-navy-900/40 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className={`mt-0.5 w-3.5 h-3.5 rounded flex items-center justify-center border shrink-0 ${isChecked ? 'bg-teal-500 border-teal-500 text-navy-950' : 'border-slate-600'}`}>
                        {isChecked && <Check size={10} strokeWidth={3} />}
                      </div>
                      <div>
                        <div className="font-semibold text-slate-200">{conv.name}</div>
                        <div className="text-[10px] text-slate-500">{conv.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* 3. Judge & Scoring Configuration */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-navy-800 pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Evaluation Judge Configuration</h2>
            <button
              type="button"
              onClick={() => setUseLlmJudge(!useLlmJudge)}
              className={`text-xs px-2.5 py-1 rounded font-semibold transition-colors ${
                useLlmJudge 
                  ? 'bg-teal-500 text-navy-950' 
                  : 'bg-navy-800 text-slate-400 border border-slate-700'
              }`}
            >
              {useLlmJudge ? 'LLM Likert Judge (1-5 Scale)' : 'Fast Heuristic Refusal Filter'}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Local Ollama Judge Model
              </label>
              <input
                type="text"
                className="input-base font-mono text-xs"
                value={judgeModel}
                onChange={e => setJudgeModel(e.target.value)}
                placeholder="qwen2.5:3b"
                disabled={!useLlmJudge}
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Ollama API Endpoint
              </label>
              <input
                type="text"
                className="input-base font-mono text-xs"
                value={ollamaUrl}
                onChange={e => setOllamaUrl(e.target.value)}
                placeholder="http://localhost:11434/api/chat"
                disabled={!useLlmJudge}
              />
            </div>
          </div>
        </div>

        {/* 4. Payload Pack Selector */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-navy-800 pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Select OWASP Payload Packs ({selectedPacks.length} selected)
            </h2>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={selectAllPacks}
                className="text-xs text-teal-400 hover:text-teal-300 font-medium"
              >
                Select All
              </button>
              <span className="text-slate-600">|</span>
              <button
                type="button"
                onClick={clearAllPacks}
                className="text-xs text-slate-400 hover:text-slate-300 font-medium"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="space-y-4 max-h-96 overflow-y-auto pr-1">
            {Object.entries(groupedPacks).map(([category, categoryPacks]) => (
              <div key={category} className="space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
                  {category}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {categoryPacks.map(pack => {
                    const isSelected = selectedPacks.includes(pack.name);
                    const isCommunity = pack.is_community || pack.source === 'community-import' || pack.name.startsWith('community_');
                    return (
                      <div
                        key={pack.name}
                        onClick={() => togglePack(pack.name)}
                        className={`p-3 rounded-lg border flex flex-col justify-between cursor-pointer transition-all ${
                          isSelected
                            ? 'border-teal-500 bg-teal-950/20 text-white shadow-sm'
                            : 'border-navy-800 bg-navy-950/40 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2 mb-1.5 flex-wrap">
                          <div className="flex items-center gap-1.5">
                            <OwaspBadge owaspId={pack.owasp_id} />
                            {isCommunity && (
                              <span className="text-[10px] font-bold font-mono text-purple-300 bg-purple-950/80 px-1.5 py-0.5 rounded border border-purple-700/60 uppercase flex items-center gap-1">
                                <Sparkles size={10} /> Community
                              </span>
                            )}
                          </div>
                          <div className={`w-3.5 h-3.5 rounded flex items-center justify-center border shrink-0 ${isSelected ? 'bg-teal-500 border-teal-500 text-navy-950' : 'border-slate-600'}`}>
                            {isSelected && <Check size={10} strokeWidth={3} />}
                          </div>
                        </div>
                        <div className="font-mono text-xs text-slate-200 font-semibold truncate" title={pack.name}>
                          {pack.name === 'handwritten_quick_50' ? 'Handwritten Multi-Vector (50)' :
                           pack.name === 'jbb_jailbreak_50' ? 'JailbreakBench Harmful (50)' :
                           pack.name === 'jailbreak' ? 'Safety Jailbreak Baseline' :
                           pack.name === 'multiturn_jailbreak' ? 'Multi-Turn Jailbreak Dialogue' :
                           pack.name === 'prompt_injection' ? 'Prompt Injection Baseline' :
                           pack.name === 'sensitive_data_leak' ? 'Sensitive Data Leak Baseline' :
                           pack.name === 'jbb_harmful' ? 'JailbreakBench Harmful Full' :
                           pack.name === 'jbb_benign' ? 'JailbreakBench Benign Ref' :
                           pack.name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-1 flex justify-between">
                          <span>{pack.count} vectors</span>
                          <span className="font-mono text-[10px] text-slate-500">{pack.name}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 5. Execution Rate & Concurrency Controls */}
        <div className="card p-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <label className="block font-semibold text-slate-300 mb-1">
                Concurrency {targetType === 'browser' ? '(1 for Browser Mode)' : '(Max Async Workers)'}
              </label>
              <input
                type="number"
                min="1"
                max="20"
                className="input-base"
                value={targetType === 'browser' ? 1 : concurrency}
                onChange={e => setConcurrency(Number(e.target.value))}
                disabled={targetType === 'browser'}
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-300 mb-1">Inter-Request Delay (Seconds)</label>
              <input
                type="number"
                min="0"
                step="0.1"
                className="input-base"
                value={delay}
                onChange={e => setDelay(Number(e.target.value))}
              />
            </div>
            <div>
              <label className="block font-semibold text-slate-300 mb-1">Limit Payloads (Empty for All)</label>
              <input
                type="number"
                min="1"
                className="input-base"
                value={limit}
                onChange={e => setLimit(e.target.value)}
                placeholder="e.g. 50"
              />
            </div>
          </div>
        </div>

        {/* Start Scan Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="btn-secondary text-sm"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting || selectedPacks.length === 0}
            className="btn-primary flex items-center gap-2 text-sm px-6 py-2.5 shadow-lg shadow-teal-500/20"
          >
            {isSubmitting ? (
              <>Initiating Scan Engine...</>
            ) : (
              <>
                <Play size={16} /> Start Scan Execution
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
