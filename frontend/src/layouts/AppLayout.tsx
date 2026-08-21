// App layout: left sidebar + top header + main content area
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Plus,
  Activity,
  AlertTriangle,
  FileText,
  Package,
  Database,
  Shield,
} from 'lucide-react';

const navItems = [
  { to: '/',              label: 'Dashboard',      icon: LayoutDashboard },
  { to: '/scan/new',      label: 'New Scan',        icon: Plus },
  { to: '/scan/live',     label: 'Live Scan',       icon: Activity },
  { to: '/findings',      label: 'Findings',        icon: AlertTriangle },
  { to: '/reports',       label: 'Reports',         icon: FileText },
  { to: '/payloads',      label: 'Payload Library', icon: Package },
  { to: '/datasets',      label: 'Dataset Tools',   icon: Database },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--navy-950)' }}>
      {/* ── Sidebar ── */}
      <aside
        className="w-56 shrink-0 flex flex-col border-r"
        style={{ background: 'var(--navy-900)', borderColor: 'rgba(30,61,113,0.6)' }}
      >
        {/* Logo / branding */}
        <div
          className="flex items-center gap-3 px-4 py-4 border-b"
          style={{ borderColor: 'rgba(30,61,113,0.6)' }}
        >
          <Shield size={22} className="text-teal-500 shrink-0" />
          <div className="min-w-0">
            <div className="text-xs text-slate-400 font-medium leading-none">LLM</div>
            <div className="text-sm font-bold text-white leading-tight truncate">SENTINEL</div>
          </div>
        </div>

        {/* Nav links */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={15} className="shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t text-[10px] text-slate-600" style={{ borderColor: 'rgba(30,61,113,0.4)' }}>
          OWASP LLM Top 10 · v1.0
        </div>
      </aside>

      {/* ── Main area ── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header
          className="h-14 shrink-0 flex items-center justify-between px-6 border-b"
          style={{ background: 'var(--navy-900)', borderColor: 'rgba(30,61,113,0.6)' }}
        >
          {/* CTS branding slot */}
          <div className="flex items-center gap-3">
            {/* Logo image slot — user places real file at frontend/public/cts-logo.png */}
            <img
              src="/cts-logo.png"
              alt="CTS"
              className="h-7 object-contain"
              onError={(e) => {
                // Hide the img if logo file is missing — text wordmark remains
                (e.target as HTMLImageElement).style.display = 'none';
              }}
            />
            <span className="text-base font-bold tracking-tight text-white">
              CTS Hackathon
            </span>
            <span
              className="text-xs font-medium px-2 py-0.5 rounded"
              style={{ background: 'rgba(20,184,166,0.15)', color: 'var(--teal-400)' }}
            >
              LLM Security Scanner
            </span>
          </div>

          {/* Right side: status indicator placeholder */}
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-500">Demo Mode</span>
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 live-dot" />
              <span className="text-xs text-slate-400">Backend Connected</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
