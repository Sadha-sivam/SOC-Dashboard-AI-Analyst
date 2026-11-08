import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  AlertOctagon,
  Activity,
  Server,
  Target,
  Sparkles,
  Settings,
  GitBranch,
} from 'lucide-react';
import clsx from 'clsx';
import { API_URL } from '../lib/api';

// Routes are unchanged; only labels were clarified.
const navItems = [
  { name: 'Overview', path: '/', icon: LayoutDashboard },
  { name: 'Alert Queue', path: '/alerts', icon: Activity },
  { name: 'Investigations', path: '/incidents', icon: AlertOctagon },
  { name: 'Attack Stories', path: '/stories', icon: GitBranch },
  { name: 'Endpoints', path: '/endpoints', icon: Server },
  { name: 'MITRE ATT&CK', path: '/mitre', icon: Target },
  { name: 'AI Analyst', path: '/ai-analyst', icon: Sparkles },
  { name: 'Settings', path: '/settings', icon: Settings },
];

function useBackendStatus() {
  const [up, setUp] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const r = await fetch(`${API_URL}/api/health`);
        if (alive) setUp(r.ok);
      } catch {
        if (alive) setUp(false);
      }
    };
    void check();
    const t = window.setInterval(check, 15000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);
  return up;
}

export default function Sidebar() {
  const up = useBackendStatus();
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-950 md:flex">
      <div className="flex items-center gap-3 border-b border-slate-800 px-5 py-5">
        <div className="rounded-lg bg-sky-500/10 p-2 ring-1 ring-sky-500/30">
          <Shield className="h-5 w-5 text-sky-400" />
        </div>
        <div>
          <h1 className="text-sm font-semibold tracking-wide text-white">SOC Investigator</h1>
          <p className="text-[11px] text-slate-500">Wazuh · Attack Intelligence</p>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 p-3">
        {navItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-sky-500/10 text-sky-300 ring-1 ring-inset ring-sky-500/20'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-100',
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.name}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-slate-800 px-5 py-4 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'h-2 w-2 rounded-full',
              up === null ? 'bg-slate-600' : up ? 'bg-emerald-400 shadow-[0_0_6px] shadow-emerald-400/70' : 'bg-red-500',
            )}
          />
          {up === null ? 'Checking backend…' : up ? 'Backend connected' : 'Backend unreachable'}
        </div>
      </div>
    </aside>
  );
}

/** Compact navigation for small screens (the sidebar is hidden below md). */
export function MobileNav() {
  return (
    <nav className="flex gap-1 overflow-x-auto border-b border-slate-800 bg-slate-950 px-3 py-2 md:hidden" aria-label="Primary">
      {navItems.map((item) => (
        <NavLink
          key={item.name}
          to={item.path}
          end={item.path === '/'}
          className={({ isActive }) =>
            clsx(
              'flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium',
              isActive ? 'bg-sky-500/10 text-sky-300' : 'text-slate-400',
            )
          }
        >
          <item.icon className="h-3.5 w-3.5" />
          {item.name}
        </NavLink>
      ))}
    </nav>
  );
}
