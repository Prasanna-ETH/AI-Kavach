// Shared UI Components for LLM Sentinel Dashboard
import React from 'react';
import { AlertCircle, Loader2, ShieldAlert, ShieldCheck } from 'lucide-react';

// ─── Severity badge ─────────────────────────────────────────────────────────

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toUpperCase();
  const cls =
    s === 'CRITICAL' ? 'severity-critical' :
    s === 'HIGH'     ? 'severity-high'     :
    s === 'MEDIUM'   ? 'severity-medium'   :
                       'severity-low';
  return (
    <span className={`${cls} text-xs font-semibold px-2 py-0.5 rounded`}>
      {s}
    </span>
  );
}

// ─── Vulnerable / safe badge ─────────────────────────────────────────────────

export function VulnBadge({ vulnerable }: { vulnerable: boolean }) {
  return vulnerable ? (
    <span className="badge-vuln flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded">
      <ShieldAlert size={11} /> VULNERABLE
    </span>
  ) : (
    <span className="badge-safe flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded">
      <ShieldCheck size={11} /> SAFE
    </span>
  );
}

// ─── Scan status chip ─────────────────────────────────────────────────────────

export function StatusChip({ status }: { status: string }) {
  const cls =
    status === 'running' ? 'status-running' :
    status === 'done'    ? 'status-done'    :
    status === 'error'   ? 'status-error'   :
                           'status-pending';
  return (
    <span className={`${cls} text-xs font-semibold px-2 py-0.5 rounded capitalize`}>
      {status === 'running' && (
        <span className="live-dot inline-block w-1.5 h-1.5 bg-teal-500 rounded-full mr-1 align-middle" />
      )}
      {status}
    </span>
  );
}

// ─── OWASP ID badge ──────────────────────────────────────────────────────────

export function OwaspBadge({ owaspId }: { owaspId: string }) {
  return (
    <span className="bg-[rgba(20,184,166,0.12)] text-teal-400 border border-[rgba(20,184,166,0.25)] text-xs font-mono font-semibold px-2 py-0.5 rounded">
      {owaspId}
    </span>
  );
}

// ─── Likert score pip ─────────────────────────────────────────────────────────

export function LikertScore({ score }: { score: number }) {
  const colors = ['#10B981', '#60D4A0', '#F59E0B', '#F97316', '#EF4444'];
  const labels = ['0/4 SAFE', '1/4 BENIGN', '2/4 WARN', '3/4 HIGH', '4/4 CRIT'];
  const color = colors[Math.min(score, 4)];
  return (
    <span style={{ color }} className="text-xs font-mono font-semibold">
      {labels[Math.min(score, 4)]}
    </span>
  );
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

export function ProgressBar({ progress, total }: { progress: number; total: number }) {
  const pct = total > 0 ? Math.round((progress / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-slate-400">
        <span>{progress} / {total} payloads</span>
        <span>{pct}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ─── Error banner ─────────────────────────────────────────────────────────────

export function ErrorBanner({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  return (
    <div className="flex items-start gap-3 bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.3)] rounded-lg p-4">
      <AlertCircle size={18} className="text-red-400 mt-0.5 shrink-0" />
      <div className="flex-1 text-sm text-red-300">{message}</div>
      {onDismiss && (
        <button onClick={onDismiss} className="text-red-400 hover:text-red-300 text-xs shrink-0">✕</button>
      )}
    </div>
  );
}

// ─── Spinner ─────────────────────────────────────────────────────────────────

export function Spinner({ size = 20, className = '' }: { size?: number; className?: string }) {
  return <Loader2 size={size} className={`spinner text-teal-500 ${className}`} />;
}

// ─── Loading state ───────────────────────────────────────────────────────────

export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <Spinner size={32} />
      <p className="text-slate-400 text-sm">{message}</p>
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────────

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
      {icon && <div className="text-slate-600">{icon}</div>}
      <div>
        <h3 className="text-lg font-semibold text-slate-300">{title}</h3>
        {description && <p className="text-slate-500 text-sm mt-1 max-w-sm">{description}</p>}
      </div>
      {action}
    </div>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────

export function SectionHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-xl font-bold text-white">{title}</h1>
        {subtitle && <p className="text-slate-400 text-sm mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  sub,
  color = 'text-white',
  icon,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  color?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div className="card p-5 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</span>
        {icon && <span className="text-slate-600">{icon}</span>}
      </div>
      <span className={`text-3xl font-bold ${color}`}>{value}</span>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
    </div>
  );
}

// ─── Collapsible row ─────────────────────────────────────────────────────────

export function Collapsible({
  trigger,
  children,
}: {
  trigger: React.ReactNode;
  children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div>
      <div onClick={() => setOpen((p) => !p)} className="cursor-pointer select-none">
        {trigger}
      </div>
      {open && children}
    </div>
  );
}

// ─── Token usage badge ────────────────────────────────────────────────────────

export function TokenBadge({
  total = 0,
  targetPrompt = 0,
  targetCompletion = 0,
  judgePrompt = 0,
  judgeCompletion = 0,
}: {
  total?: number;
  targetPrompt?: number;
  targetCompletion?: number;
  judgePrompt?: number;
  judgeCompletion?: number;
}) {
  const targetTotal = (targetPrompt || 0) + (targetCompletion || 0);
  const judgeTotal = (judgePrompt || 0) + (judgeCompletion || 0);
  const totalTokens = total || (targetTotal + judgeTotal);

  return (
    <div className="inline-flex items-center gap-1.5 text-[11px] font-mono bg-navy-950 px-2 py-0.5 rounded border border-navy-800 text-slate-300">
      <span className="text-teal-400 font-bold">{totalTokens.toLocaleString()} tok</span>
      <span className="text-slate-600">·</span>
      <span className="text-slate-400 text-[10px]" title={`Target: ${targetTotal} (Prompt: ${targetPrompt}, Output: ${targetCompletion})`}>
        🎯{targetTotal}
      </span>
      {judgeTotal > 0 ? (
        <span className="text-amber-400/90 text-[10px]" title={`Judge: ${judgeTotal} (Prompt: ${judgePrompt}, Output: ${judgeCompletion})`}>
          ⚖️{judgeTotal}
        </span>
      ) : (
        <span className="text-emerald-400 text-[10px]" title="Judge skipped via fast heuristic pre-filter (100% token savings)">
          ⚡0
        </span>
      )}
    </div>
  );
}

// ─── Token telemetry summary banner ──────────────────────────────────────────

export function TokenMetricsBanner({
  totalTokens = 0,
  targetTokens = 0,
  judgeTokens = 0,
  tokensSaved = 0,
}: {
  totalTokens?: number;
  targetTokens?: number;
  judgeTokens?: number;
  tokensSaved?: number;
}) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-navy-950/70 p-3 rounded-lg border border-navy-800/80 font-mono text-xs">
      <div className="flex flex-col">
        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Total Consumed</span>
        <span className="text-sm font-bold text-teal-400">
          {(totalTokens || 0).toLocaleString()} <span className="text-[10px] text-slate-500 font-normal">tok</span>
        </span>
      </div>
      <div className="flex flex-col border-l border-navy-800/60 pl-3">
        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">🎯 Target Endpoint</span>
        <span className="text-sm font-bold text-slate-200">
          {(targetTokens || 0).toLocaleString()} <span className="text-[10px] text-slate-500 font-normal">tok</span>
        </span>
      </div>
      <div className="flex flex-col border-l border-navy-800/60 pl-3">
        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">⚖️ Judge Evaluator</span>
        <span className="text-sm font-bold text-amber-400">
          {(judgeTokens || 0).toLocaleString()} <span className="text-[10px] text-slate-500 font-normal">tok</span>
        </span>
      </div>
      <div className="flex flex-col border-l border-navy-800/60 pl-3">
        <span className="text-[10px] uppercase font-bold text-emerald-500/90 tracking-wider">⚡ Heuristic Saved</span>
        <span className="text-sm font-bold text-emerald-400">
          +{(tokensSaved || 0).toLocaleString()} <span className="text-[10px] text-emerald-500/70 font-normal">tok</span>
        </span>
      </div>
    </div>
  );
}
