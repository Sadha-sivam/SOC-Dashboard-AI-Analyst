import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import clsx from 'clsx';
import { SEVERITY_STYLE, asSeverity } from '../lib/severity';

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={clsx('rounded-xl border border-slate-800 bg-slate-900/70 shadow-sm', className)}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div>
            {title && <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-200">{title}</h2>}
            {description && <p className="mt-1 text-xs text-slate-500">{description}</p>}
          </div>
          {actions}
        </div>
      )}
      <div className={clsx('p-5', bodyClassName)}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  accent = 'text-slate-300',
  bar,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: LucideIcon;
  accent?: string;
  bar?: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/70 p-5">
      {bar && <span className={clsx('absolute inset-y-0 left-0 w-1', bar)} />}
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</p>
        {Icon && <Icon className={clsx('h-4 w-4', accent)} />}
      </div>
      <p className="mt-3 text-3xl font-semibold tabular-nums text-white">{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const sev = asSeverity(severity);
  const s = SEVERITY_STYLE[sev];
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide',
        s.badge,
        className,
      )}
    >
      <span className={clsx('h-1.5 w-1.5 rounded-full', s.dot)} />
      {s.label}
    </span>
  );
}

export function ErrorBanner({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-red-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">
        <p className="text-sm font-semibold">{title}</p>
        <p className="mt-1 text-sm text-red-300/90">{message}</p>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="rounded-md border border-red-400/40 px-3 py-1 text-xs hover:bg-red-500/10">
          Retry
        </button>
      )}
    </div>
  );
}

export function RefreshButton({ onClick, loading }: { onClick: () => void; loading: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
    >
      <RefreshCw className={clsx('h-4 w-4', loading && 'animate-spin')} />
      Refresh
    </button>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">{children}</div>;
}
