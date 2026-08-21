import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Layers, 
  Plus, 
  ChevronRight, 
  RefreshCw,
  Clock,
  Flame
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis 
} from 'recharts';
import { api } from '../api/client';
import type { ScanSummary } from '../types';
import { 
  StatCard, 
  StatusChip, 
  SectionHeader, 
  LoadingState, 
  ErrorBanner, 
  EmptyState 
} from '../components';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  HIGH: '#F87171',
  MEDIUM: '#F59E0B',
  LOW: '#10B981',
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.listScans();
      setScans(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  if (loading) {
    return <LoadingState message="Loading scanner analytics & history..." />;
  }

  // Aggregate stats across all scans
  const totalScans = scans.length;
  const totalPayloadsTested = scans.reduce((acc, s) => acc + (s.total || 0), 0);
  const totalVulnerabilities = scans.reduce((acc, s) => acc + (s.vulnerable_count || 0), 0);
  const totalTokensConsumed = scans.reduce((acc, s) => acc + (s.total_tokens || 0), 0);
  const totalTokensSaved = scans.reduce((acc, s) => acc + (s.judge_tokens_saved || 0), 0);
  
  // Aggregate severity counts
  const aggregatedSeverity: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  scans.forEach(s => {
    if (s.severity_counts) {
      Object.entries(s.severity_counts).forEach(([sev, count]) => {
        const k = sev.toUpperCase();
        if (aggregatedSeverity[k] !== undefined) {
          aggregatedSeverity[k] += count;
        }
      });
    }
  });

  const severityPieData = Object.entries(aggregatedSeverity)
    .filter(([_, count]) => count > 0)
    .map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] || '#94A3B8' }));

  // Posture score from the most recent completed scan
  const latestCompletedScan = scans.find(s => s.status === 'done');
  const latestPostureScore = latestCompletedScan?.posture_score ?? null;
  const latestGrade = latestCompletedScan?.grade ?? null;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <SectionHeader
        title="Security Posture Dashboard"
        subtitle="Real-time LLM vulnerability diagnostics & benchmark monitoring"
        actions={
          <div className="flex gap-2">
            <button 
              onClick={fetchScans} 
              className="btn-secondary flex items-center gap-1 text-xs"
              title="Refresh data"
            >
              <RefreshCw size={13} /> Refresh
            </button>
            <button 
              onClick={() => navigate('/scan/new')} 
              className="btn-primary flex items-center gap-1.5 text-xs shadow-lg shadow-teal-500/10"
            >
              <Plus size={14} /> Start New Scan
            </button>
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {scans.length === 0 ? (
        <div className="card p-12 mt-8">
          <EmptyState
            icon={<ShieldAlert size={48} className="text-teal-500/50 mb-2" />}
            title="No Scans Executed Yet"
            description="Run your first automated vulnerability scan against your target model or API endpoint to generate security posture analytics."
            action={
              <button 
                onClick={() => navigate('/scan/new')} 
                className="btn-primary flex items-center gap-2 mt-4 text-sm"
              >
                <Plus size={16} /> Configure & Run Scan
              </button>
            }
          />
        </div>
      ) : (
        <>
          {/* Top KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <StatCard
              label="Total Scans Run"
              value={totalScans}
              sub={`${scans.filter(s => s.status === 'running').length} in progress`}
              icon={<Activity size={18} />}
            />
            <StatCard
              label="Payloads Evaluated"
              value={totalPayloadsTested}
              sub="Across all attack vectors"
              icon={<Layers size={18} />}
            />
            <StatCard
              label="Vulnerabilities Flagged"
              value={totalVulnerabilities}
              sub={`${aggregatedSeverity.CRITICAL} Critical severity`}
              color={totalVulnerabilities > 0 ? "text-red-400" : "text-emerald-400"}
              icon={<Flame size={18} className="text-red-400" />}
            />
            <StatCard
              label="Tokens Consumed"
              value={totalTokensConsumed > 0 ? `${(totalTokensConsumed / 1000).toFixed(1)}k` : '0'}
              sub={totalTokensSaved > 0 ? `+${(totalTokensSaved / 1000).toFixed(1)}k saved via heuristics` : 'Target + Judge tokens'}
              color="text-teal-400"
              icon={<Clock size={18} className="text-teal-400" />}
            />
            <StatCard
              label="Latest Posture Grade"
              value={latestGrade ? `${latestGrade} (${latestPostureScore?.toFixed(1)})` : 'N/A'}
              sub={latestCompletedScan ? `Target: ${latestCompletedScan.target_url.slice(0, 18)}...` : 'No completed scans'}
              color={latestGrade === 'A' ? 'text-emerald-400' : latestGrade === 'F' ? 'text-red-400' : 'text-amber-400'}
              icon={<ShieldCheck size={18} className="text-teal-400" />}
            />
          </div>

          {/* Analytics Visualizations */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Severity Distribution Donut */}
            <div className="card p-5 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide mb-1">Findings by Severity</h3>
                <p className="text-xs text-slate-400 mb-4">Total breakdown across all vulnerabilities detected</p>
              </div>
              <div className="h-52 w-full flex items-center justify-center">
                {severityPieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityPieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {severityPieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} stroke="#0B1F3A" strokeWidth={2} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ background: '#0D2047', border: '1px solid #1E3D71', borderRadius: '6px', fontSize: '12px' }} 
                        itemStyle={{ color: '#E2E8F0' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-xs text-slate-500 flex flex-col items-center">
                    <ShieldCheck size={32} className="text-emerald-500/40 mb-1" />
                    <span>No vulnerabilities recorded</span>
                  </div>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-navy-800">
                {Object.entries(aggregatedSeverity).map(([sev, count]) => (
                  <div key={sev} className="flex items-center justify-between text-xs px-2.5 py-1 bg-navy-950/60 rounded border border-navy-800/40">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[sev] }} />
                      <span className="text-slate-400 font-medium">{sev}</span>
                    </div>
                    <span className="font-mono font-bold text-white">{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Scans Performance Chart */}
            <div className="card p-5 lg:col-span-2 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide mb-1">Recent Scan Security Posture</h3>
                <p className="text-xs text-slate-400 mb-4">Historical posture scores (0-100 scale) for recent scans</p>
              </div>
              <div className="h-56 w-full">
                {scans.some(s => s.posture_score !== undefined && s.posture_score !== null) ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={scans.slice(0, 8).reverse().map((s, idx) => ({
                        id: `Scan #${idx + 1}`,
                        score: s.posture_score ?? 0,
                        vulnerabilities: s.vulnerable_count || 0,
                      }))}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <XAxis dataKey="id" stroke="#64748B" fontSize={11} tickLine={false} />
                      <YAxis domain={[0, 100]} stroke="#64748B" fontSize={11} tickLine={false} />
                      <Tooltip
                        contentStyle={{ background: '#0D2047', border: '1px solid #1E3D71', borderRadius: '6px', fontSize: '12px' }}
                        itemStyle={{ color: '#E2E8F0' }}
                      />
                      <Bar dataKey="score" fill="#14B8A6" radius={[4, 4, 0, 0]} name="Posture Score" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500">
                    Run completed scans to populate historical posture analytics
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Recent Scans Table */}
          <div className="card overflow-hidden">
            <div className="p-4 border-b border-navy-800 flex justify-between items-center bg-navy-900/50">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Clock size={16} className="text-teal-400" />
                Recent Security Scans
              </h3>
              <button 
                onClick={() => navigate('/reports')} 
                className="text-xs text-teal-400 hover:text-teal-300 flex items-center gap-1 font-semibold transition-colors"
              >
                View all reports <ChevronRight size={13} />
              </button>
            </div>
            <div className="data-table-container border-none rounded-none">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Scan ID / Target</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Payloads</th>
                    <th>Vulnerabilities</th>
                    <th>Score / Grade</th>
                    <th>Tokens</th>
                    <th>Timestamp</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 5).map((scan) => (
                    <tr key={scan.scan_id} className="cursor-pointer hover:bg-navy-800/40" onClick={() => navigate(scan.status === 'running' ? `/scan/live?id=${scan.scan_id}` : `/findings?id=${scan.scan_id}`)}>
                      <td>
                        <div className="font-mono text-xs text-teal-400">{scan.scan_id.slice(0, 8)}...</div>
                        <div className="text-xs text-slate-400 truncate max-w-xs">{scan.target_url}</div>
                      </td>
                      <td>
                        <span className="text-xs font-mono uppercase bg-navy-800 px-2 py-0.5 rounded text-slate-300">
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
                      <td>
                        <span className="text-xs font-mono text-teal-400">
                          {scan.total_tokens ? `${scan.total_tokens.toLocaleString()} tok` : '-'}
                        </span>
                      </td>
                      <td className="text-xs text-slate-400">
                        {scan.start_time ? new Date(scan.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-'}
                      </td>
                      <td className="text-right">
                        <button 
                          className="btn-secondary text-xs px-2 py-1"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(scan.status === 'running' ? `/scan/live?id=${scan.scan_id}` : `/findings?id=${scan.scan_id}`);
                          }}
                        >
                          {scan.status === 'running' ? 'Live Monitor' : 'Inspect'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
