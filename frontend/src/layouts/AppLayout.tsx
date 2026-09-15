// App layout: responsive sidebar drawer + top header + main content area
import { useState } from 'react';
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
  Menu,
  X,
  Radio
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--navy-950)' }}>
      {/* ── Desktop Sidebar ── */}
      <aside
        className="hidden md:flex w-60 shrink-0 flex-col border-r z-20"
        style={{ background: 'var(--navy-900)', borderColor: 'rgba(25,53,90,0.8)' }}
      >
        {/* Logo / branding */}
        <div
          className="flex items-center gap-3 px-5 py-4 border-b"
          style={{ borderColor: 'rgba(25,53,90,0.8)' }}
        >
          <div className="p-2 rounded-lg bg-teal-500/15 border border-teal-500/30 text-teal-400">
            <Shield size={20} />
          </div>
          <div className="min-w-0">
            <div className="text-[10px] text-teal-400 font-bold uppercase tracking-wider leading-none">ASFALIS</div>
            <div className="text-sm font-extrabold text-white leading-tight truncate tracking-tight">LLM Sentinel</div>
          </div>
        </div>

        {/* Nav links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={16} className="shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t text-[10px] text-slate-500 flex items-center justify-between" style={{ borderColor: 'rgba(25,53,90,0.6)' }}>
          <span className="font-mono">OWASP LLM Top 10</span>
          <span className="bg-navy-800 px-1.5 py-0.5 rounded text-slate-400 font-mono">v1.0</span>
        </div>
      </aside>

      {/* ── Mobile Drawer Overlay ── */}
      {mobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-navy-950/80 backdrop-blur-sm z-40 md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* ── Mobile Sidebar Drawer ── */}
      <aside
        className={`fixed top-0 bottom-0 left-0 w-64 z-50 flex flex-col border-r transform transition-transform duration-300 ease-in-out md:hidden ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        style={{ background: 'var(--navy-900)', borderColor: 'rgba(25,53,90,0.9)' }}
      >
        <div className="flex items-center justify-between px-4 py-4 border-b border-navy-800">
          <div className="flex items-center gap-2.5">
            <Shield size={20} className="text-teal-400" />
            <span className="font-bold text-white text-sm">LLM Sentinel</span>
          </div>
          <button 
            onClick={() => setMobileMenuOpen(false)}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-navy-800"
          >
            <X size={18} />
          </button>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={16} className="shrink-0" />
              <span className="truncate">{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      {/* ── Main content area ── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        <header
          className="h-14 shrink-0 flex items-center justify-between px-4 md:px-6 border-b z-10"
          style={{ background: 'rgba(11, 25, 44, 0.95)', borderColor: 'rgba(25,53,90,0.8)' }}
        >
          {/* Mobile hamburger + branding */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="p-1.5 text-slate-300 hover:text-white rounded-lg hover:bg-navy-800 md:hidden"
              aria-label="Toggle Navigation Menu"
            >
              <Menu size={20} />
            </button>

            {/* CTS logo & badge */}
            <div className="flex items-center gap-2 sm:gap-3">
              <img
                src="/cts-logo.png"
                alt="CTS"
                className="h-6 sm:h-7 object-contain"
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
              <span className="text-sm sm:text-base font-extrabold tracking-tight text-white">
                CTS Hackathon
              </span>
              <span
                className="hidden sm:inline-flex text-[11px] font-semibold px-2 py-0.5 rounded-full border border-teal-500/30"
                style={{ background: 'rgba(20,184,166,0.12)', color: 'var(--teal-400)' }}
              >
                AI LLM Scanner
              </span>
            </div>
          </div>

          {/* Right side status indicators */}
          <div className="flex items-center gap-2 sm:gap-4">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-navy-950 border border-navy-800 text-xs text-slate-400">
              <Radio size={12} className="text-teal-400" />
              <span>Demo Mode</span>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/40 border border-emerald-800/40 text-xs text-emerald-400 font-medium">
              <div className="w-2 h-2 rounded-full bg-emerald-400 live-dot" />
              <span className="hidden sm:inline">Backend Connected</span>
              <span className="sm:hidden">Live</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  );
}

