import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertOctagon, GitMerge, Server, ShieldAlert, Sparkles } from 'lucide-react';
import { getJson, formatTime, timeAgo } from '../lib/api';
import { SEVERITY_ORDER, SEVERITY_STYLE, severityFromLevel, type Severity } from '../lib/severity';
import { EmptyState, ErrorBanner, PageHeader, Panel, RefreshButton, SeverityBadge, StatCard } from '../components/ui';

// recharts is loaded on demand so it stays out of the initial bundle.
const TrendChart = lazy(() => import('../components/TrendChart'));

interface Alert {
  id: string;
  timestamp: string | null;
  ruleId: string;
  level: number;
  description: string;
  agentName: string;
  agentId: string;
}
interface Story {
  id: string;
  title: string;
  target: string;
  eventCount: number;
  lastSeen: string;
  severity: string;
}
interface Endpoint {
  id: string;
  name: string;
  status: string;
  operatingSystem?: string;
}
interface Summary {
  total: number;
  totalIsLowerBound?: boolean;
  severity: Record<string, number>;
  trend: Array<{ time: string; total: number; critical: number; high: number }>;
  interval: string;
  topRules: Array<{ ruleId: string; count: number; description: string; level: number }>;
}

/** Fallback used only if /api/alerts/summary is unavailable (e.g. older backend): derived from the alert list. */
function summaryFromAlerts(alerts: Alert[]): Summary {
  const severity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const buckets = new Map<number, { total: number; critical: number; high: number }>();
  const rules = new Map<string, { count: number; description: string; level: number }>();
  for (const a of alerts) {
    const sev = severityFromLevel(a.level).toLowerCase();
    severity[sev]++;
    const t = a.timestamp ? new Date(a.timestamp) : null;
    if (t && !Number.isNaN(t.getTime())) {
      t.setMinutes(0, 0, 0);
      const b = buckets.get(t.getTime()) ?? { total: 0, critical: 0, high: 0 };
      b.total++;
      if (sev === 'critical') b.critical++;
      if (sev === 'high') b.high++;
      buckets.set(t.getTime(), b);
    }
    const r = rules.get(a.ruleId) ?? { count: 0, description: a.description, level: a.level };
    r.count++;
    rules.set(a.ruleId, r);
  }
  return {
    total: alerts.length,
    severity,
    interval: '1h',
    trend: [...buckets.entries()].sort((x, y) => x[0] - y[0]).map(([k, v]) => ({ time: new Date(k).toISOString(), ...v })),
    topRules: [...rules.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8).map(([ruleId, v]) => ({ ruleId, ...v })),
  };
}

export default function Overview() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stories, setStories] = useState<Story[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [summaryFallback, setSummaryFallback] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [a, s, e] = await Promise.all([
        getJson<{ alerts: Alert[] }>('/api/alerts'),
        getJson<{ stories: Story[] }>('/api/stories'),
        getJson<{ endpoints: Endpoint[] }>('/api/agents'),
      ]);
      if (!Array.isArray(a.alerts) || !Array.isArray(s.stories) || !Array.isArray(e.endpoints)) {
        throw new Error('The backend returned an unexpected data format.');
      }
      setAlerts(a.alerts);
      setStories(s.stories);
      setEndpoints(e.endpoints);
      try {
        setSummary(await getJson<Summary>('/api/alerts/summary?hours=24'));
        setSummaryFallback(false);
      } catch {
        setSummary(summaryFromAlerts(a.alerts));
        setSummaryFallback(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load live dashboard data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const t = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(t);
  }, [load]);

  const sev = summary?.severity ?? {};
  const activeEndpoints = endpoints.filter((e) => e.status.toLowerCase() === 'active').length;
  const disconnected = endpoints.filter((e) => e.status.toLowerCase() === 'disconnected').length;
  const needsReview = stories.filter((s) => ['HIGH', 'CRITICAL'].includes(s.severity)).length;

  const recent = useMemo(
    () =>
      [...alerts]
        .sort((a, b) => new Date(b.timestamp ?? 0).getTime() - new Date(a.timestamp ?? 0).getTime())
        .slice(0, 8),
    [alerts],
  );

  const trend = (summary?.trend ?? []).map((p) => ({
    ...p,
    label: new Date(p.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));
  const dash = loading && !summary ? '…' : error && !summary ? '—' : undefined;
  const fmt = (n: number | undefined) => dash ?? (n ?? 0).toLocaleString();
  const total = summary?.total ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOC Command Center"
        subtitle="Live data from the Wazuh Indexer for the last 24 hours. Correlated groups are triage aids that require analyst review, not confirmed attacks."
        actions={
          <>
            <Link
              to="/ai-analyst"
              className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm font-medium text-slate-950 hover:bg-sky-400"
            >
              <Sparkles className="h-4 w-4" /> Ask AI Analyst
            </Link>
            <RefreshButton onClick={() => void load()} loading={loading} />
          </>
        }
      />

      {error && (
        <ErrorBanner
          title="Live data unavailable"
          message={`${error} The dashboard will not substitute demo numbers for missing data.`}
          onRetry={() => void load()}
        />
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Total raw alerts"
          value={fmt(total)}
          icon={Activity}
          hint={summaryFallback ? 'From alert list (capped at 1,000)' : 'Last 24h · exact count'}
          bar="bg-slate-500"
        />
        <StatCard label="Critical" value={fmt(sev.critical)} bar="bg-red-500" accent="text-red-400" icon={ShieldAlert} hint="Rule level 12+" />
        <StatCard label="High" value={fmt(sev.high)} bar="bg-orange-500" accent="text-orange-400" hint="Level 10–11" />
        <StatCard label="Medium" value={fmt(sev.medium)} bar="bg-amber-400" accent="text-amber-300" hint="Level 7–9" />
        <StatCard label="Low" value={fmt(sev.low)} bar="bg-sky-400" accent="text-sky-300" hint="Level 4–6" />
        <StatCard
          label="Investigations"
          value={loading && !error ? '…' : error ? '—' : stories.length.toLocaleString()}
          icon={GitMerge}
          accent="text-sky-400"
          bar="bg-sky-500"
          hint={`${needsReview} high/critical to review`}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Panel
          title="Alert trend"
          description={`Alerts per ${summary?.interval ?? 'hour'}, last 24 hours`}
          className="xl:col-span-2"
        >
          {trend.length === 0 ? (
            <EmptyState>{loading ? 'Loading trend…' : 'No alerts in the selected window.'}</EmptyState>
          ) : (
            <Suspense fallback={<div className="h-64 animate-pulse rounded-lg bg-slate-800/40" />}>
              <TrendChart data={trend} />
            </Suspense>
          )}
        </Panel>

        <Panel title="Severity distribution" description="Share of alerts by Wazuh rule level">
          <div className="space-y-3">
            {SEVERITY_ORDER.map((s: Severity) => {
              const count = sev[s.toLowerCase()] ?? 0;
              const pct = total ? (count / total) * 100 : 0;
              return (
                <div key={s}>
                  <div className="mb-1 flex justify-between text-xs">
                    <span className="text-slate-300">{SEVERITY_STYLE[s].label}</span>
                    <span className="tabular-nums text-slate-400">
                      {count.toLocaleString()} · {pct.toFixed(1)}%
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: SEVERITY_STYLE[s].hex }} />
                  </div>
                </div>
              );
            })}
          </div>
          <p className="mt-5 text-xs text-slate-500">
            "Investigations" are groups of events on one endpoint within five-minute windows. They are not verified attacks.
          </p>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Panel
          title="Recent security activity"
          className="xl:col-span-2"
          actions={
            <Link to="/alerts" className="text-xs text-sky-400 hover:text-sky-300">
              Open Alert Queue →
            </Link>
          }
          bodyClassName="p-0"
        >
          {recent.length === 0 ? (
            <div className="p-5">
              <EmptyState>{loading ? 'Loading alerts…' : 'No alerts were returned by the API.'}</EmptyState>
            </div>
          ) : (
            <ul className="divide-y divide-slate-800">
              {recent.map((a) => (
                <li key={a.id}>
                  <Link to={`/alerts?open=${encodeURIComponent(a.id)}`} className="flex items-start gap-4 px-5 py-3 hover:bg-slate-800/40">
                    <SeverityBadge severity={severityFromLevel(a.level)} className="mt-0.5 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-slate-200">{a.description}</p>
                      <p className="mt-0.5 text-xs text-slate-500">
                        {a.agentName} · Rule {a.ruleId} · Level {a.level}
                      </p>
                    </div>
                    <time className="shrink-0 text-xs text-slate-500" title={formatTime(a.timestamp)}>
                      {timeAgo(a.timestamp) || '—'}
                    </time>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Endpoints" description="From the Wazuh manager API">
          <div className="mb-4 grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-slate-950 p-3">
              <Server className="mb-2 h-4 w-4 text-emerald-400" />
              <p className="text-2xl font-semibold text-white">{loading || error ? '—' : activeEndpoints}</p>
              <p className="text-xs text-slate-400">Active</p>
            </div>
            <div className="rounded-lg bg-slate-950 p-3">
              <AlertOctagon className="mb-2 h-4 w-4 text-amber-400" />
              <p className="text-2xl font-semibold text-white">{loading || error ? '—' : disconnected}</p>
              <p className="text-xs text-slate-400">Disconnected</p>
            </div>
          </div>
          <ul className="space-y-3">
            {endpoints.map((e) => (
              <li key={e.id} className="flex items-start justify-between gap-3 border-t border-slate-800 pt-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-200">{e.name}</p>
                  <p className="truncate text-xs text-slate-500">{e.operatingSystem || 'Operating system unavailable'}</p>
                </div>
                <span
                  className={`rounded-md px-2 py-0.5 text-xs ${
                    e.status.toLowerCase() === 'active'
                      ? 'bg-emerald-500/10 text-emerald-300'
                      : e.status.toLowerCase() === 'disconnected'
                        ? 'bg-amber-500/10 text-amber-300'
                        : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {e.status}
                </span>
              </li>
            ))}
            {!loading && !error && endpoints.length === 0 && <p className="text-sm text-slate-400">No endpoint data returned.</p>}
          </ul>
        </Panel>
      </div>

      {summary && summary.topRules.length > 0 && (
        <Panel title="Top detection rules" description="Most frequent rules in the last 24 hours" bodyClassName="p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-5 py-3">Rule</th>
                  <th className="px-5 py-3">Description</th>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3 text-right">Alerts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {summary.topRules.map((r) => (
                  <tr key={r.ruleId} className="hover:bg-slate-800/30">
                    <td className="px-5 py-2.5 font-mono text-xs text-slate-400">{r.ruleId}</td>
                    <td className="px-5 py-2.5 text-slate-200">{r.description}</td>
                    <td className="px-5 py-2.5"><SeverityBadge severity={severityFromLevel(r.level)} /></td>
                    <td className="px-5 py-2.5 text-right tabular-nums text-slate-300">{r.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
