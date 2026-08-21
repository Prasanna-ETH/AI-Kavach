import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { 
  ChevronDown, 
  ChevronRight, 
  ArrowRight,
  Layers,
  Terminal,
  Activity,
  RefreshCw,
  RotateCw,
  CheckCircle2,
  Pencil,
  X as XIcon
} from 'lucide-react';
import { api, openScanStream } from '../api/client';
import type { Finding, ScanSummary } from '../types';
import { 
  SectionHeader, 
  StatusChip, 
  SeverityBadge, 
  VulnBadge, 
  LikertScore, 
  OwaspBadge, 
  ProgressBar, 
  ErrorBanner, 
  EmptyState,
  TokenBadge,
  TokenMetricsBanner,
  Spinner
} from '../components';

export default function LiveScan() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanId = searchParams.get('id');

  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
  const [streamActive, setStreamActive] = useState(true);
  const [activeTurnStatus, setActiveTurnStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Retest state
  const [retestingKey, setRetestingKey] = useState<string | null>(null);
  const [retestMessage, setRetestMessage] = useState<string | null>(null);

  // Editable prompt state: rowKey -> current textarea value
  const [editingPrompts, setEditingPrompts] = useState<Record<string, string>>({});
  // Which rowKeys are in edit mode
  const [editModeKeys, setEditModeKeys] = useState<Set<string>>(new Set());

  // If no ID in URL, fetch most recent running or most recent scan
  useEffect(() => {
    if (!scanId) {
      api.listScans().then(scans => {
        if (scans.length > 0) {
          const running = scans.find(s => s.status === 'running') || scans[0];
          navigate(`/scan/live?id=${running.scan_id}`, { replace: true });
        }
      }).catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to fetch scans'));
    }
  }, [scanId, navigate]);

  // Initial fetch + SSE stream
  useEffect(() => {
    if (!scanId) return;

    let cleanupStream: (() => void) | undefined;

    const init = async () => {
      try {
        const summary = await api.getScan(scanId);
        setScanSummary(summary);

        const initialFindings = await api.getFindings(scanId);
        setLiveFindings(initialFindings);

        if (summary.status === 'done' || summary.status === 'error') {
          setStreamActive(false);
          return;
        }

        // Open live SSE stream
        cleanupStream = openScanStream(
          scanId,
          (eventType, data) => {
            if (eventType === 'total_set') {
              setScanSummary(prev => prev ? { ...prev, total: (data.total as number) } : null);
            } else if (eventType === 'payload_started') {
              setActiveTurnStatus(`Executing [${data.payload_id}] (${data.category})...`);
            } else if (eventType === 'turn_update') {
              setActiveTurnStatus(
                `Payload ${data.payload_id} — Turn ${data.current_turn}/${data.max_turns}: ${data.status_msg}`
              );
            } else if (eventType === 'finding') {
              const finding = data.finding as Finding;
              setLiveFindings(prev => {
                const exists = prev.some(f => f.payload_id === finding.payload_id && f.converter_used === finding.converter_used);
                return exists ? prev : [finding, ...prev];
              });
              setScanSummary(prev => {
                if (!prev) return null;
                return {
                  ...prev,
                  progress: (data.index as number) || (prev.progress + 1),
                  total: (data.total as number) || prev.total,
                  vulnerable_count: finding.vulnerable ? prev.vulnerable_count + 1 : prev.vulnerable_count,
                  total_target_tokens: (prev.total_target_tokens || 0) + (finding.target_prompt_tokens || 0) + (finding.target_completion_tokens || 0),
                  total_judge_tokens: (prev.total_judge_tokens || 0) + (finding.judge_prompt_tokens || 0) + (finding.judge_completion_tokens || 0),
                  total_tokens: (prev.total_tokens || 0) + (finding.total_tokens || 0),
                };
              });
            } else if (eventType === 'scan_complete') {
              const finalSummary = data as unknown as ScanSummary;
              setScanSummary(finalSummary);
              setStreamActive(false);
              setActiveTurnStatus('Scan execution complete.');
            } else if (eventType === 'scan_error') {
              setError((data.error as string) || 'Scan execution failed');
              setStreamActive(false);
            }
          },
          () => {
            setStreamActive(false);
          }
        );
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to connect to scan monitor');
        setStreamActive(false);
      }
    };

    init();

    return () => {
      if (cleanupStream) cleanupStream();
    };
  }, [scanId]);

  const toggleRow = (id: string) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleRetest = async (e: React.MouseEvent, finding: Finding, overridePrompt?: string) => {
    e.stopPropagation();
    if (!scanId) return;

    const rowKey = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
    const promptToSend = overridePrompt ?? finding.prompt;
    try {
      setRetestingKey(rowKey);
      setRetestMessage(null);

      const updated = await api.retestPayload(scanId, finding.payload_id, {
        prompt: promptToSend,
        converter_used: finding.converter_used,
      });

      setLiveFindings(prev => prev.map(f => {
        const k = `${f.payload_id}-${f.converter_used || 'plain'}`;
        return k === rowKey ? updated : f;
      }));

      // Exit edit mode and clear custom prompt after successful retest
      setEditModeKeys(prev => { const s = new Set(prev); s.delete(rowKey); return s; });
      setEditingPrompts(prev => { const n = { ...prev }; delete n[rowKey]; return n; });

      setRetestMessage(`Payload ${finding.payload_id} Retested: ${updated.vulnerable ? '🔴 Vulnerable' : '✅ Passed'}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Retest request failed');
    } finally {
      setRetestingKey(null);
    }
  };

  if (!scanId) {
    return (
      <div className="card p-12 max-w-4xl mx-auto mt-8">
        <EmptyState
          icon={<Activity size={48} className="text-teal-500/40 mb-2" />}
          title="No Active Scan Selected"
          description="Select a scan to inspect or start a new security audit."
          action={
            <button onClick={() => navigate('/scan/new')} className="btn-primary mt-4 text-xs">
              Configure New Scan
            </button>
          }
        />
      </div>
    );
  }

  // Calculate live token aggregates
  const totalTargetTokens = scanSummary?.total_target_tokens ?? liveFindings.reduce((acc, f) => acc + (f.target_prompt_tokens || 0) + (f.target_completion_tokens || 0), 0);
  const totalJudgeTokens = scanSummary?.total_judge_tokens ?? liveFindings.reduce((acc, f) => acc + (f.judge_prompt_tokens || 0) + (f.judge_completion_tokens || 0), 0);
  const totalTokens = scanSummary?.total_tokens ?? (totalTargetTokens + totalJudgeTokens);
  const tokensSaved = scanSummary?.judge_tokens_saved ?? liveFindings.filter(f => ['fast_prefilter', 'signature_engine', 'refusal_engine', 'heuristic'].includes(f.judge_type)).length * 280;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <SectionHeader
        title="Live Scan Execution Monitor"
        subtitle={scanSummary ? `Target: ${scanSummary.target_url}` : `Scan ID: ${scanId}`}
        actions={
          <div className="flex items-center gap-3">
            {scanSummary?.status === 'done' && (
              <button
                onClick={() => navigate(`/findings?id=${scanId}`)}
                className="btn-primary text-xs flex items-center gap-1.5"
              >
                Inspect All Findings <ArrowRight size={13} />
              </button>
            )}
            <button
              onClick={() => navigate('/scan/new')}
              className="btn-secondary text-xs"
            >
              New Scan
            </button>
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* Monitor Header Status Box */}
      <div className="card p-6 border-navy-700 bg-navy-900 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-navy-800 pb-4">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${streamActive ? 'bg-teal-400 live-dot' : scanSummary?.status === 'done' ? 'bg-emerald-400' : 'bg-red-400'}`} />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-teal-400 font-bold">{scanId.slice(0, 8)}</span>
                <StatusChip status={scanSummary?.status || (streamActive ? 'running' : 'pending')} />
                <span className="text-xs uppercase font-mono px-2 py-0.5 bg-navy-800 text-slate-300 rounded">
                  {scanSummary?.scan_mode || 'single'} mode
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono truncate max-w-lg">
                {scanSummary?.target_url}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 text-xs">
            <div className="text-right">
              <span className="text-slate-500 block">Vulnerabilities Detected</span>
              <span className={`text-lg font-bold ${scanSummary && scanSummary.vulnerable_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {scanSummary?.vulnerable_count ?? 0}
              </span>
            </div>
            {scanSummary?.posture_score !== undefined && scanSummary.posture_score !== null && (
              <div className="text-right border-l border-navy-800 pl-6">
                <span className="text-slate-500 block">Posture Grade</span>
                <span className="text-lg font-bold text-white">
                  {scanSummary.grade} ({scanSummary.posture_score.toFixed(1)})
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Progress bar */}
        <ProgressBar
          progress={scanSummary?.progress ?? liveFindings.length}
          total={scanSummary?.total ?? liveFindings.length}
        />

        {/* Token Telemetry Metrics Bar */}
        <TokenMetricsBanner
          totalTokens={totalTokens}
          targetTokens={totalTargetTokens}
          judgeTokens={totalJudgeTokens}
          tokensSaved={tokensSaved}
        />

        {/* Live Engine Action Status */}
        {activeTurnStatus && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-navy-950/80 px-3 py-2 rounded border border-navy-800">
            <Terminal size={14} className="text-teal-400 shrink-0" />
            <span className="truncate">{activeTurnStatus}</span>
          </div>
        )}
      </div>

      {/* Live Payloads Stream Table */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-navy-800 flex justify-between items-center bg-navy-900/60">
          <div className="flex items-center gap-2">
            <Layers size={16} className="text-teal-400" />
            <h3 className="text-sm font-semibold text-white">
              Evaluated Payloads & Attack Vectors ({liveFindings.length})
            </h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            {streamActive ? 'Live SSE stream connected' : 'Stream closed'}
          </span>
        </div>

        {/* Notification Toast for Retest */}
        {retestMessage && (
          <div className="p-3 bg-teal-950/60 border border-teal-800 text-teal-300 text-xs rounded-lg flex items-center justify-between font-mono animate-fadeIn mx-4 mt-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} className="text-teal-400 shrink-0" />
              <span>{retestMessage}</span>
            </div>
            <button onClick={() => setRetestMessage(null)} className="text-slate-400 hover:text-white text-xs">Dismiss</button>
          </div>
        )}

        <div className="data-table-container border-none rounded-none">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '40px' }}></th>
                <th>Payload ID</th>
                <th>OWASP / Category</th>
                <th>Attack Prompt Preview</th>
                <th>Likert Score</th>
                <th>Outcome</th>
                <th>Judge Mechanism</th>
                <th>Token Usage</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {liveFindings.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-12 text-xs text-slate-500">
                    <Activity size={24} className="mx-auto mb-2 text-slate-600 animate-pulse" />
                    Waiting for initial payload dispatches from scan engine...
                  </td>
                </tr>
              ) : (
                liveFindings.map((finding, idx) => {
                  const rowKey = `${finding.payload_id}-${finding.converter_used || 'plain'}-${idx}`;
                  const retestKey = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                  const isExpanded = !!expandedRows[rowKey];
                  const isRetestingThis = retestingKey === retestKey;

                  return (
                    <React.Fragment key={rowKey}>
                      <tr 
                        className={`cursor-pointer transition-colors ${
                          isRetestingThis
                            ? 'bg-teal-950/40 animate-pulse'
                            : 'hover:bg-navy-800/50'
                        }`}
                        onClick={() => toggleRow(rowKey)}
                      >
                        <td className="text-slate-500">
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>
                        <td>
                          <div className="font-mono text-xs font-bold text-teal-400">
                            {finding.payload_id}
                          </div>
                          {finding.converter_used && (
                            <span className="text-[10px] bg-navy-800 text-teal-300 px-1.5 py-0.2 rounded border border-teal-800/40">
                              {finding.converter_used}
                            </span>
                          )}
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5 mb-1">
                            <OwaspBadge owaspId={finding.owasp_id} />
                          </div>
                          <div className="text-[11px] text-slate-400 truncate max-w-[140px]">
                            {finding.category}
                          </div>
                        </td>
                        <td>
                          <div className="text-xs text-slate-300 font-mono truncate max-w-sm">
                            {finding.prompt || (finding.full_transcript && finding.full_transcript.length > 0 ? finding.full_transcript[0].content : 'N/A')}
                          </div>
                        </td>
                        <td>
                          <LikertScore score={finding.likert_score} />
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <VulnBadge vulnerable={finding.vulnerable} />
                            {finding.vulnerable && <SeverityBadge severity={finding.severity} />}
                          </div>
                        </td>
                        <td>
                          <span className="text-xs font-mono text-slate-400 bg-navy-950 px-2 py-0.5 rounded border border-navy-800">
                            {finding.judge_type}
                          </span>
                        </td>
                        <td>
                          <TokenBadge
                            total={finding.total_tokens}
                            targetPrompt={finding.target_prompt_tokens}
                            targetCompletion={finding.target_completion_tokens}
                            judgePrompt={finding.judge_prompt_tokens}
                            judgeCompletion={finding.judge_completion_tokens}
                          />
                        </td>
                        <td className="text-right">
                          <button
                            type="button"
                            onClick={e => handleRetest(e, finding)}
                            disabled={isRetestingThis}
                            title="Re-send prompt vector to target LLM endpoint & re-evaluate judge verdict"
                            className="btn-secondary text-[11px] py-1 px-2.5 inline-flex items-center gap-1.5 hover:border-teal-500 hover:text-teal-300 transition-all"
                          >
                            {isRetestingThis ? (
                              <>
                                <Spinner size={12} /> Retesting...
                              </>
                            ) : (
                              <>
                                <RefreshCw size={12} className="text-teal-400" /> Retest
                              </>
                            )}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Turn Transcript / Details */}
                      {isExpanded && (
                        <tr className="bg-navy-950/80 border-b border-navy-800">
                          <td colSpan={9} className="p-4 space-y-3">
                            {!finding.full_transcript ? (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              <div className="space-y-1">
                                  <div className="font-semibold text-slate-400 flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2">
                                      <span>Attack Prompt Sent:</span>
                                      {finding.sent_prompt && finding.sent_prompt !== finding.prompt && (
                                        <span className="text-[10px] text-teal-400">Obfuscated Variant</span>
                                      )}
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                      {editModeKeys.has(`${finding.payload_id}-${finding.converter_used || 'plain'}`) ? (
                                        <button
                                          type="button"
                                          onClick={e => {
                                            e.stopPropagation();
                                            const k = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                                            setEditModeKeys(prev => { const s = new Set(prev); s.delete(k); return s; });
                                            setEditingPrompts(prev => { const n = { ...prev }; delete n[k]; return n; });
                                          }}
                                          className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1 px-1.5 py-0.5 rounded border border-navy-700 hover:border-slate-600 transition-colors"
                                        >
                                          <XIcon size={10} /> Cancel Edit
                                        </button>
                                      ) : (
                                        <button
                                          type="button"
                                          onClick={e => {
                                            e.stopPropagation();
                                            const k = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                                            setEditModeKeys(prev => new Set(prev).add(k));
                                            setEditingPrompts(prev => ({ ...prev, [k]: finding.sent_prompt || finding.prompt || '' }));
                                          }}
                                          className="text-[10px] text-teal-400 hover:text-teal-300 flex items-center gap-1 px-1.5 py-0.5 rounded border border-teal-900/50 hover:border-teal-700 transition-colors"
                                          title="Edit prompt before retesting"
                                        >
                                          <Pencil size={10} /> Edit Prompt
                                        </button>
                                      )}
                                    </div>
                                  </div>

                                  {editModeKeys.has(`${finding.payload_id}-${finding.converter_used || 'plain'}`) ? (
                                    <textarea
                                      className="w-full p-2.5 bg-navy-900 rounded font-mono text-slate-100 border border-teal-700/60 text-xs resize-y min-h-[120px] max-h-64 focus:outline-none focus:ring-1 focus:ring-teal-500 transition-colors"
                                      value={editingPrompts[`${finding.payload_id}-${finding.converter_used || 'plain'}`] ?? (finding.sent_prompt || finding.prompt || '')}
                                      onClick={e => e.stopPropagation()}
                                      onChange={e => {
                                        const k = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                                        setEditingPrompts(prev => ({ ...prev, [k]: e.target.value }));
                                      }}
                                      spellCheck={false}
                                      placeholder="Enter custom attack prompt..."
                                    />
                                  ) : (
                                    <div className="p-2.5 bg-navy-900 rounded font-mono text-slate-200 border border-navy-800 whitespace-pre-wrap max-h-48 overflow-y-auto">
                                      {finding.sent_prompt || finding.prompt}
                                    </div>
                                  )}
                                </div>

                                <div className="space-y-1">
                                  <div className="font-semibold text-slate-400">Target Model Response:</div>
                                  <div className="p-2.5 bg-navy-900 rounded font-mono text-slate-300 border border-navy-800 whitespace-pre-wrap max-h-48 overflow-y-auto">
                                    {finding.response_text || (finding.error ? `ERROR: ${finding.error}` : 'No response text returned')}
                                  </div>
                                </div>

                                <div className="md:col-span-2 p-3 bg-navy-900/50 rounded border border-navy-800 text-xs">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="font-semibold text-teal-400">Judge Reasoning:</span>
                                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                                      <span>Target: <strong className="text-slate-200">{(finding.target_prompt_tokens || 0) + (finding.target_completion_tokens || 0)}</strong> (p:{finding.target_prompt_tokens || 0}, c:{finding.target_completion_tokens || 0})</span>
                                      <span>Judge: <strong className="text-amber-400">{(finding.judge_prompt_tokens || 0) + (finding.judge_completion_tokens || 0)}</strong> (p:{finding.judge_prompt_tokens || 0}, c:{finding.judge_completion_tokens || 0})</span>
                                      <span>Total: <strong className="text-teal-400">{finding.total_tokens || 0}</strong> tok</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-300">{finding.reasoning || 'No explanation recorded'}</p>
                                </div>

                                <div className="md:col-span-2 flex justify-end gap-2 pt-1">
                                  {editModeKeys.has(`${finding.payload_id}-${finding.converter_used || 'plain'}`) && (
                                    <button
                                      type="button"
                                      onClick={e => {
                                        const k = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                                        handleRetest(e, finding, editingPrompts[k]);
                                      }}
                                      disabled={isRetestingThis}
                                      className="btn-primary text-xs px-4 py-2 inline-flex items-center gap-2 border-teal-500"
                                    >
                                      {isRetestingThis ? (
                                        <>
                                          <Spinner size={14} /> Retesting...
                                        </>
                                      ) : (
                                        <>
                                          <Pencil size={13} /> Retest with Edited Prompt
                                        </>
                                      )}
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    onClick={e => handleRetest(e, finding)}
                                    disabled={isRetestingThis}
                                    className="btn-secondary text-xs px-4 py-2 inline-flex items-center gap-2"
                                  >
                                    {isRetestingThis ? (
                                      <>
                                        <Spinner size={14} /> Retesting Target Endpoint...
                                      </>
                                    ) : (
                                      <>
                                        <RotateCw size={14} /> Re-send Original Prompt
                                      </>
                                    )}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="space-y-3">
                                <div className="flex items-center justify-between text-xs border-b border-navy-800 pb-2">
                                  <span className="font-semibold text-teal-400">
                                    Multi-Turn Adversarial Dialog ({finding.full_transcript.length} turns)
                                  </span>
                                  <div className="flex items-center gap-3">
                                    <span className="text-[11px] font-mono text-slate-400">
                                      Total Tokens: <strong className="text-teal-400">{finding.total_tokens || 0}</strong> tok
                                    </span>
                                    {finding.succeeded_at_turn && (
                                      <span className="text-red-400 font-semibold bg-red-950/60 px-2 py-0.5 rounded border border-red-800/40">
                                        Vulnerability Exploited at Turn {finding.succeeded_at_turn}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                                  {finding.full_transcript.map((turn, tIdx) => (
                                    <div 
                                      key={tIdx} 
                                      className={`p-3 rounded text-xs font-mono border ${
                                        turn.role === 'attacker'
                                          ? 'bg-navy-900 border-teal-900/40 text-teal-200'
                                          : 'bg-navy-950 border-navy-800 text-slate-300'
                                      }`}
                                    >
                                      <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                                        <span className="font-bold uppercase tracking-wider text-slate-400">
                                          Turn {turn.turn_number} · {turn.role === 'attacker' ? 'Attacker Red-Team Prompt' : 'Target Endpoint Response'}
                                        </span>
                                        {turn.prompt_tokens ? (
                                          <span>{turn.prompt_tokens} tok</span>
                                        ) : turn.completion_tokens ? (
                                          <span>{turn.completion_tokens} tok</span>
                                        ) : null}
                                      </div>
                                      <div className="whitespace-pre-wrap">{turn.content}</div>
                                    </div>
                                  ))}
                                </div>

                                <div className="p-3 bg-navy-900/50 rounded border border-navy-800 text-xs">
                                  <span className="font-semibold text-teal-400 block mb-1">Multi-Turn Judge Assessment:</span>
                                  <p className="text-slate-300">{finding.reasoning}</p>
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
