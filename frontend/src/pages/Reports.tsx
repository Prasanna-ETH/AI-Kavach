import { useEffect, useState } from 'react';
import { 
  FileText, 
  Download, 
  ExternalLink, 
  RefreshCw, 
  Table as TableIcon
} from 'lucide-react';
import { api } from '../api/client';
import type { ScanSummary, EvalMetrics } from '../types';
import { 
  SectionHeader, 
  StatusChip, 
  StatCard, 
  LoadingState, 
  ErrorBanner, 
  EmptyState 
} from '../components';

export default function Reports() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Optional sample eval metrics if user previously ran eval-judge
  const [evalMetrics] = useState<EvalMetrics | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const list = await api.listScans();
      setScans(list);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scan reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  if (loading) {
    return <LoadingState message="Loading generated security reports and metrics..." />;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <SectionHeader
        title="Security Reports & Benchmark Evaluations"
        subtitle="Export executive HTML/JSON audit reports and inspect offline judge evaluations"
        actions={
          <button 
            onClick={fetchScans} 
            className="btn-secondary text-xs flex items-center gap-1.5"
          >
            <RefreshCw size={13} /> Refresh List
          </button>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* 1. Evaluation Benchmark Metrics (if present) */}
      {evalMetrics && (
        <div className="card p-6 space-y-5 border-teal-800/40 bg-navy-900">
          <div className="flex items-center justify-between border-b border-navy-800 pb-3">
            <div className="flex items-center gap-2">
              <TableIcon size={18} className="text-teal-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Judge Evaluation Benchmark Metrics
              </h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">JailbreakBench Comparison</span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              label="Overall Accuracy"
              value={`${(evalMetrics.accuracy * 100).toFixed(1)}%`}
              color="text-emerald-400"
            />
            <StatCard
              label="Precision"
              value={`${(evalMetrics.precision * 100).toFixed(1)}%`}
              color="text-teal-400"
            />
            <StatCard
              label="Recall"
              value={`${(evalMetrics.recall * 100).toFixed(1)}%`}
              color="text-teal-400"
            />
            <StatCard
              label="F1 Score"
              value={evalMetrics.f1_score.toFixed(3)}
              color="text-cyan-400"
            />
          </div>

          {/* 2x2 Confusion Matrix Grid */}
          <div className="pt-2">
            <h4 className="text-xs font-semibold text-slate-300 mb-3">Confusion Matrix (2x2 Grid)</h4>
            <div className="max-w-md mx-auto grid grid-cols-2 gap-3 text-center text-xs">
              <div className="p-4 bg-emerald-950/40 border border-emerald-800/50 rounded-lg">
                <span className="text-slate-400 block mb-1">True Positives (TP)</span>
                <span className="text-2xl font-bold font-mono text-emerald-400">{evalMetrics.true_positives}</span>
                <span className="text-[10px] text-slate-500 block mt-1">Harmful identified correctly</span>
              </div>
              <div className="p-4 bg-red-950/40 border border-red-800/50 rounded-lg">
                <span className="text-slate-400 block mb-1">False Positives (FP)</span>
                <span className="text-2xl font-bold font-mono text-red-400">{evalMetrics.false_positives}</span>
                <span className="text-[10px] text-slate-500 block mt-1">Benign flagged as harmful</span>
              </div>
              <div className="p-4 bg-amber-950/40 border border-amber-800/50 rounded-lg">
                <span className="text-slate-400 block mb-1">False Negatives (FN)</span>
                <span className="text-2xl font-bold font-mono text-amber-400">{evalMetrics.false_negatives}</span>
                <span className="text-[10px] text-slate-500 block mt-1">Harmful missed by judge</span>
              </div>
              <div className="p-4 bg-emerald-950/40 border border-emerald-800/50 rounded-lg">
                <span className="text-slate-400 block mb-1">True Negatives (TN)</span>
                <span className="text-2xl font-bold font-mono text-emerald-400">{evalMetrics.true_negatives}</span>
                <span className="text-[10px] text-slate-500 block mt-1">Benign passed correctly</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. Audit Scans Reports Table */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-navy-800 flex justify-between items-center bg-navy-900/60">
          <div className="flex items-center gap-2">
            <FileText size={16} className="text-teal-400" />
            <h3 className="text-sm font-semibold text-white">Generated Scan Reports ({scans.length})</h3>
          </div>
        </div>

        {scans.length === 0 ? (
          <div className="p-12">
            <EmptyState
              icon={<FileText size={48} className="text-slate-600 mb-2" />}
              title="No Reports Generated"
              description="Execute your first scan to generate downloadable HTML and structured JSON reports."
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan ID / Target</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Payloads</th>
                  <th>Vulnerabilities</th>
                  <th>Posture Score</th>
                  <th>Timestamp</th>
                  <th className="text-right">Download Reports</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(scan => (
                  <tr key={scan.scan_id} className="hover:bg-navy-800/40">
                    <td>
                      <div className="font-mono text-xs font-bold text-teal-400">{scan.scan_id.slice(0, 8)}...</div>
                      <div className="text-xs text-slate-400 truncate max-w-xs">{scan.target_url}</div>
                    </td>
                    <td>
                      <span className="text-xs uppercase font-mono bg-navy-800 px-2 py-0.5 rounded text-slate-300">
                        {scan.scan_mode}
                      </span>
                    </td>
                    <td>
                      <StatusChip status={scan.status} />
                    </td>
                    <td className="text-xs font-mono text-slate-300">
                      {scan.progress} / {scan.total}
                    </td>
                    <td>
                      {scan.vulnerable_count > 0 ? (
                        <span className="text-xs font-semibold text-red-400 bg-red-950/40 border border-red-800/50 px-2 py-0.5 rounded">
                          {scan.vulnerable_count} Vuln
                        </span>
                      ) : (
                        <span className="text-xs text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded">
                          0 Vuln
                        </span>
                      )}
                    </td>
                    <td>
                      {scan.grade ? (
                        <span className="text-xs font-bold text-white">
                          Grade {scan.grade} ({scan.posture_score?.toFixed(1)})
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">-</span>
                      )}
                    </td>
                    <td className="text-xs text-slate-400">
                      {scan.start_time ? new Date(scan.start_time).toLocaleString() : '-'}
                    </td>
                    <td className="text-right">
                      {scan.status === 'done' ? (
                        <div className="flex items-center justify-end gap-2">
                          <a
                            href={api.reportHtmlUrl(scan.scan_id)}
                            target="_blank"
                            rel="noreferrer"
                            className="btn-secondary text-xs px-2.5 py-1 flex items-center gap-1"
                            title="Open standalone HTML report in new tab"
                          >
                            <ExternalLink size={12} /> HTML
                          </a>
                          <a
                            href={api.reportJsonUrl(scan.scan_id)}
                            download
                            className="btn-secondary text-xs px-2.5 py-1 flex items-center gap-1"
                            title="Download JSON report payload"
                          >
                            <Download size={12} /> JSON
                          </a>
                        </div>
                      ) : (
                        <span className="text-xs text-slate-500">Processing...</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
