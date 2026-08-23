import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Search, 
  ChevronDown, 
  ChevronRight, 
  Download, 
  ShieldAlert,
  RefreshCw,
  RotateCw,
  CheckCircle2
} from 'lucide-react';
import { api } from '../api/client';
import type { Finding, ScanSummary } from '../types';
import { 
  SectionHeader, 
  SeverityBadge, 
  VulnBadge, 
  LikertScore, 
  OwaspBadge, 
  ErrorBanner, 
  LoadingState, 
  EmptyState,
  TokenBadge,
  TokenMetricsBanner,
  ConfidenceBadge,
  Spinner
} from '../components';

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanId = searchParams.get('id');

  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(scanId || '');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Retest state
  const [retestingKey, setRetestingKey] = useState<string | null>(null);
  const [retestMessage, setRetestMessage] = useState<string | null>(null);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Row Expand State
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  // 1. Fetch available scans list
  useEffect(() => {
    async function loadScansList() {
      try {
        const list = await api.listScans();
        setScans(list);
        if (!selectedScanId && list.length > 0) {
          setSelectedScanId(list[0].scan_id);
          setSearchParams({ id: list[0].scan_id });
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to fetch scan list');
      }
    }
    loadScansList();
  }, [selectedScanId, setSearchParams]);

  // 2. Fetch findings when selectedScanId changes
  useEffect(() => {
    if (!selectedScanId) return;

    async function loadFindings() {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getFindings(selectedScanId);
        setFindings(data);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load findings for this scan');
      } finally {
        setLoading(false);
      }
    }
    loadFindings();
  }, [selectedScanId]);

  const handleScanChange = (id: string) => {
    setSelectedScanId(id);
    setSearchParams({ id });
  };

  const toggleRow = (id: string) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const availableCategories = Array.from(new Set(findings.map(f => f.category))).filter(Boolean);

  const filteredFindings = findings.filter(f => {
    if (vulnerableOnly && !f.vulnerable) return false;
    if (severityFilter !== 'ALL' && f.severity.toUpperCase() !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchId = f.payload_id.toLowerCase().includes(q);
      const matchPrompt = f.prompt?.toLowerCase().includes(q);
      const matchResp = f.response_text?.toLowerCase().includes(q);
      const matchReasoning = f.reasoning?.toLowerCase().includes(q);
      if (!matchId && !matchPrompt && !matchResp && !matchReasoning) return false;
    }
    return true;
  });

  const selectedScan = scans.find(s => s.scan_id === selectedScanId);

  // Compute aggregate token metrics
  const totalTargetTokens = selectedScan?.total_target_tokens ?? findings.reduce((acc, f) => acc + (f.target_prompt_tokens || 0) + (f.target_completion_tokens || 0), 0);
  const totalJudgeTokens = selectedScan?.total_judge_tokens ?? findings.reduce((acc, f) => acc + (f.judge_prompt_tokens || 0) + (f.judge_completion_tokens || 0), 0);
  const totalTokens = selectedScan?.total_tokens ?? (totalTargetTokens + totalJudgeTokens);
  const tokensSaved = selectedScan?.judge_tokens_saved ?? findings.filter(f => ['fast_prefilter', 'signature_engine', 'refusal_engine', 'heuristic'].includes(f.judge_type)).length * 280;

  const handleRetest = async (e: React.MouseEvent, finding: Finding) => {
    e.stopPropagation();
    if (!selectedScanId) return;

    const rowKey = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
    try {
      setRetestingKey(rowKey);
      setRetestMessage(null);

      const updated = await api.retestPayload(selectedScanId, finding.payload_id, {
        prompt: finding.prompt,
        converter_used: finding.converter_used,
      });

      setFindings(prev => prev.map(f => {
        const k = `${f.payload_id}-${f.converter_used || 'plain'}`;
        return k === rowKey ? updated : f;
      }));

      setRetestMessage(`Retest Complete: Payload ${finding.payload_id} — ${updated.vulnerable ? '🔴 Flagged Vulnerable' : '✅ Passed Security Evaluation'}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Retest request failed');
    } finally {
      setRetestingKey(null);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <SectionHeader
        title="Security Audit Findings"
        subtitle="Granular per-payload security diagnostics, prompt transcripts, and judge verifications"
        actions={
          <div className="flex items-center gap-3">
            {selectedScanId && (
              <>
                <a
                  href={api.reportJsonUrl(selectedScanId)}
                  download
                  className="btn-secondary text-xs flex items-center gap-1"
                >
                  <Download size={13} /> Export JSON
                </a>
                <a
                  href={api.reportHtmlUrl(selectedScanId)}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary text-xs flex items-center gap-1"
                >
                  View HTML Report
                </a>
              </>
            )}
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* Top Controls: Scan Selector & Stats */}
      <div className="card p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold text-slate-300">Select Audit Run:</span>
            <select
              value={selectedScanId}
              onChange={e => handleScanChange(e.target.value)}
              className="input-base text-xs font-mono py-1.5 px-3 max-w-md"
            >
              {scans.map(s => (
                <option key={s.scan_id} value={s.scan_id}>
                  [{s.status.toUpperCase()}] {s.scan_id.slice(0, 8)} — {s.target_url.slice(0, 30)} ({s.start_time ? new Date(s.start_time).toLocaleDateString() : ''})
                </option>
              ))}
            </select>
          </div>

          {selectedScan && (
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Total:</span>
                <span className="font-mono font-bold text-white">{selectedScan.total}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400">Vulnerabilities:</span>
                <span className="font-mono font-bold text-red-400">{selectedScan.vulnerable_count}</span>
              </div>
              {selectedScan.posture_score !== undefined && selectedScan.posture_score !== null && (
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">Grade:</span>
                  <span className="font-mono font-bold text-teal-400">{selectedScan.grade} ({selectedScan.posture_score.toFixed(1)})</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Token Telemetry Bar */}
        {findings.length > 0 && (
          <TokenMetricsBanner
            totalTokens={totalTokens}
            targetTokens={totalTargetTokens}
            judgeTokens={totalJudgeTokens}
            tokensSaved={tokensSaved}
          />
        )}

        {/* Filter Bar */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-3 border-t border-navy-800">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search ID, prompt, or response..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="input-base text-xs pl-8"
            />
          </div>

          <div>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="input-base text-xs"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Severity</option>
              <option value="HIGH">High Severity</option>
              <option value="MEDIUM">Medium Severity</option>
              <option value="LOW">Low Severity</option>
            </select>
          </div>

          <div>
            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              className="input-base text-xs"
            >
              <option value="ALL">All Categories</option>
              {availableCategories.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setVulnerableOnly(!vulnerableOnly)}
              className={`text-xs px-3 py-2 rounded-md font-semibold w-full border flex items-center justify-center gap-1.5 transition-colors ${
                vulnerableOnly
                  ? 'bg-red-950/60 border-red-800 text-red-300'
                  : 'bg-navy-800 border-navy-700 text-slate-400 hover:border-slate-600'
              }`}
            >
              <ShieldAlert size={14} className={vulnerableOnly ? 'text-red-400' : 'text-slate-500'} />
              Vulnerable Only ({findings.filter(f => f.vulnerable).length})
            </button>
          </div>
        </div>
      </div>

      {/* Findings Data Table */}
      {loading ? (
        <LoadingState message="Filtering and loading findings..." />
      ) : filteredFindings.length === 0 ? (
        <div className="card p-12">
          <EmptyState
            title="No Matching Findings"
            description="No vulnerability findings matched your current filter criteria."
          />
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="p-4 border-b border-navy-800 flex justify-between items-center bg-navy-900/60 text-xs text-slate-400">
            <span>Showing {filteredFindings.length} of {findings.length} findings</span>
            <span className="font-mono text-[11px]">Click any row to expand full transcript & reasoning</span>
          </div>

        {/* Notification Toast for Retest */}
        {retestMessage && (
          <div className="p-3 bg-teal-950/60 border border-teal-800 text-teal-300 text-xs rounded-lg flex items-center justify-between font-mono animate-fadeIn">
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
                  <th style={{ width: '36px' }}></th>
                  <th>Payload ID</th>
                  <th>OWASP / Category</th>
                  <th>Prompt Preview</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Judge</th>
                  <th>Tokens</th>
                  <th>Converter</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding, idx) => {
                  const rowKey = `${finding.payload_id}-${finding.converter_used || 'plain'}-${idx}`;
                  const retestKey = `${finding.payload_id}-${finding.converter_used || 'plain'}`;
                  const isExpanded = !!expandedRows[rowKey];
                  const isRetestingThis = retestingKey === retestKey;

                  return (
                    <React.Fragment key={rowKey}>
                      <tr
                        onClick={() => toggleRow(rowKey)}
                        className={`cursor-pointer transition-colors ${
                          isRetestingThis
                            ? 'bg-teal-950/40 animate-pulse'
                            : 'hover:bg-navy-800/50'
                        }`}
                      >
                        <td className="text-slate-500">
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>
                        <td>
                          <div className="font-mono text-xs font-bold text-teal-400">
                            {finding.payload_id}
                          </div>
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5 mb-1">
                            <OwaspBadge owaspId={finding.owasp_id} />
                          </div>
                          <div className="text-[11px] text-slate-400 truncate max-w-[150px]">
                            {finding.category}
                          </div>
                        </td>
                        <td>
                          <div className="text-xs text-slate-300 font-mono truncate max-w-sm">
                            {finding.prompt || (finding.full_transcript && finding.full_transcript.length > 0 ? finding.full_transcript[0].content : 'N/A')}
                          </div>
                        </td>
                        <td>
                          <div className="flex flex-col gap-1 items-start">
                            <LikertScore score={finding.likert_score} />
                            <ConfidenceBadge confidence={finding.confidence} />
                          </div>
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5">
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
                        <td>
                          {finding.converter_used ? (
                            <span className="text-[10px] bg-navy-800 text-teal-300 font-mono px-2 py-0.5 rounded border border-teal-800/40">
                              {finding.converter_used}
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-500">Plain</span>
                          )}
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

                      {/* Expanded Details Row */}
                      {isExpanded && (
                        <tr className="bg-navy-950/90 border-b border-navy-800">
                          <td colSpan={10} className="p-5 space-y-4">
                            {!finding.full_transcript ? (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                <div className="space-y-1.5">
                                  <div className="font-semibold text-slate-300 flex items-center justify-between">
                                    <span>Exact Prompt Transmitted:</span>
                                    {finding.converter_used && (
                                      <span className="text-[10px] text-teal-400 font-mono">
                                        Converted using {finding.converter_used}
                                      </span>
                                    )}
                                  </div>
                                  <div className="p-3 bg-navy-900 rounded font-mono text-slate-200 border border-navy-800 whitespace-pre-wrap max-h-60 overflow-y-auto">
                                    {finding.sent_prompt || finding.prompt}
                                  </div>
                                </div>

                                <div className="space-y-1.5">
                                  <div className="font-semibold text-slate-300">Target Model Raw Response:</div>
                                  <div className="p-3 bg-navy-900 rounded font-mono text-slate-300 border border-navy-800 whitespace-pre-wrap max-h-60 overflow-y-auto">
                                    {finding.response_text || (finding.error ? `ERROR: ${finding.error}` : 'No response text')}
                                  </div>
                                </div>

                                <div className="md:col-span-2 p-3.5 bg-navy-900/60 rounded border border-navy-800 text-xs">
                                  <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                      <span className="font-semibold text-teal-400">
                                        Judge Evaluation Reasoning ({finding.judge_type}):
                                      </span>
                                      <ConfidenceBadge confidence={finding.confidence} />
                                    </div>
                                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                                      <span>Target: <strong className="text-slate-200">{(finding.target_prompt_tokens || 0) + (finding.target_completion_tokens || 0)}</strong> (p:{finding.target_prompt_tokens || 0}, c:{finding.target_completion_tokens || 0})</span>
                                      <span>Judge: <strong className="text-amber-400">{(finding.judge_prompt_tokens || 0) + (finding.judge_completion_tokens || 0)}</strong> (p:{finding.judge_prompt_tokens || 0}, c:{finding.judge_completion_tokens || 0})</span>
                                      <span>Total: <strong className="text-teal-400">{finding.total_tokens || 0}</strong> tok</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-300 leading-relaxed">{finding.reasoning || 'No details provided'}</p>
                                </div>

                                <div className="md:col-span-2 flex justify-end pt-2">
                                  <button
                                    type="button"
                                    onClick={e => handleRetest(e, finding)}
                                    disabled={isRetestingThis}
                                    className="btn-primary text-xs px-4 py-2 inline-flex items-center gap-2"
                                  >
                                    {isRetestingThis ? (
                                      <>
                                        <Spinner size={14} /> Retesting Target Endpoint...
                                      </>
                                    ) : (
                                      <>
                                        <RotateCw size={14} /> Re-send Vector & Retest Target Endpoint
                                      </>
                                    )}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="space-y-3">
                                <div className="flex items-center justify-between text-xs border-b border-navy-800 pb-2">
                                  <span className="font-bold text-teal-400">
                                    Full Turn-by-Turn Escalation Dialogue
                                  </span>
                                  <div className="flex items-center gap-3">
                                    <span className="text-[11px] font-mono text-slate-400">
                                      Total Tokens: <strong className="text-teal-400">{finding.total_tokens || 0}</strong> tok
                                    </span>
                                    {finding.succeeded_at_turn && (
                                      <span className="text-red-400 font-semibold bg-red-950/60 px-2 py-0.5 rounded border border-red-800/40">
                                        Breach Identified at Turn #{finding.succeeded_at_turn}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                                  {finding.full_transcript.map((turn, tIdx) => (
                                    <div
                                      key={tIdx}
                                      className={`p-3 rounded text-xs font-mono border ${
                                        turn.role === 'attacker'
                                          ? 'bg-navy-900 border-teal-900/40 text-teal-200'
                                          : 'bg-navy-950 border-navy-800 text-slate-300'
                                      }`}
                                    >
                                      <div className="text-[10px] text-slate-500 mb-1 font-bold uppercase flex justify-between">
                                        <span>Turn {turn.turn_number} · {turn.role === 'attacker' ? 'Attacker Red-Team Prompt' : 'Target Endpoint Response'}</span>
                                        {turn.prompt_tokens ? <span>{turn.prompt_tokens} tok</span> : turn.completion_tokens ? <span>{turn.completion_tokens} tok</span> : null}
                                      </div>
                                      <div className="whitespace-pre-wrap">{turn.content}</div>
                                    </div>
                                  ))}
                                </div>

                                <div className="p-3.5 bg-navy-900/60 rounded border border-navy-800 text-xs">
                                  <span className="font-semibold text-teal-400 block mb-1.5">
                                    Multi-Turn Judge Synthesis:
                                  </span>
                                  <p className="text-slate-300 leading-relaxed">{finding.reasoning}</p>
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
