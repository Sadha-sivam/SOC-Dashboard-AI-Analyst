import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Search, Sparkles, X } from 'lucide-react';
import clsx from 'clsx';
import { getJson, formatTime } from '../lib/api';
import { SEVERITY_ORDER, SEVERITY_RANK, SEVERITY_STYLE, severityFromLevel, type Severity } from '../lib/severity';
import { RESTRICTED_AGENT, setPendingAiContext } from '../lib/aiContext';
import { EmptyState, ErrorBanner, PageHeader, Panel, RefreshButton, SeverityBadge, StatCard } from '../components/ui';

type Alert = {
  id: string;
  timestamp: string | null;
  ruleId: string;
  level: number;
  description: string;
  agentName: string;
  agentId: string;
  agentIp: string;
};

type AlertResponse = { source: string; windowHours: number; count: number; alerts: Alert[] };

type AlertDetail = {
  id: string;
  severity: Severity;
  level: number;
  timestamp: string | null;
  rule: { id?: string; description?: string; level?: number; groups?: string[]; mitre?: { id?: string[]; tactic?: string[]; technique?: string[] } };
  agent: { id?: string; name?: string; ip?: string };
  data: Record<string, unknown>;
  fullLog: string | null;
  raw: Record<string, unknown>;
};

type SortKey = 'time' | 'severity' | 'agent' | 'rule';
const PAGE_SIZE = 50;

export default function Alerts() {
  const [data, setData] = useState<AlertResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<Severity | 'ALL'>('ALL');
  const [agentFilter, setAgentFilter] = useState('ALL');
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'time', dir: 'desc' });
  const [page, setPage] = useState(0);
  const [params, setParams] = useSearchParams();
  const openId = params.get('open');

  const load = useCallback(async () => {
    try {
      setError('');
      setData(await getJson<AlertResponse>('/api/alerts'));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const t = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(t);
  }, [load]);

  const all = useMemo(() => data?.alerts ?? [], [data]);
  const agents = useMemo(() => [...new Set(all.map((a) => a.agentName))].sort(), [all]);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const a of all) c[severityFromLevel(a.level)]++;
    return c;
  }, [all]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = all.filter((a) => {
      if (sevFilter !== 'ALL' && severityFromLevel(a.level) !== sevFilter) return false;
      if (agentFilter !== 'ALL' && a.agentName !== agentFilter) return false;
      if (!q) return true;
      return [a.description, a.agentName, a.agentId, a.ruleId, a.agentIp].some((v) => String(v).toLowerCase().includes(q));
    });
    const dir = sort.dir === 'asc' ? 1 : -1;
    return filtered.sort((a, b) => {
      switch (sort.key) {
        case 'severity':
          return dir * (SEVERITY_RANK[severityFromLevel(a.level)] - SEVERITY_RANK[severityFromLevel(b.level)] || a.level - b.level);
        case 'agent':
          return dir * a.agentName.localeCompare(b.agentName);
        case 'rule':
          return dir * a.ruleId.localeCompare(b.ruleId, undefined, { numeric: true });
        default:
          return dir * (new Date(a.timestamp ?? 0).getTime() - new Date(b.timestamp ?? 0).getTime());
      }
    });
  }, [all, search, sevFilter, agentFilter, sort]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, pages - 1);
  const visible = rows.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  function toggleSort(key: SortKey) {
    setPage(0);
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'time' || key === 'severity' ? 'desc' : 'asc' }));
  }

  function setOpen(id: string | null) {
    const next = new URLSearchParams(params);
    if (id) next.set('open', id);
    else next.delete('open');
    setParams(next, { replace: true });
  }

  const sortHead = (k: SortKey, label: string) => (
    <th className="px-4 py-3">
      <button onClick={() => toggleSort(k)} className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-slate-200">
        {label}
        {sort.key === k && (sort.dir === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
      </button>
    </th>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alert Queue"
        subtitle={`Events retrieved from the Wazuh Indexer (last ${data?.windowHours ?? 24}h). Select a row for the full event. Refreshes every 15 seconds.`}
        actions={<RefreshButton onClick={() => void load()} loading={loading} />}
      />

      {error && <ErrorBanner title="Could not load Wazuh alerts" message={error} onRetry={() => void load()} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {SEVERITY_ORDER.map((s) => (
          <button key={s} onClick={() => { setSevFilter(sevFilter === s ? 'ALL' : s); setPage(0); }} className="text-left">
            <StatCard
              label={SEVERITY_STYLE[s].label}
              value={loading && !data ? '…' : counts[s].toLocaleString()}
              bar={SEVERITY_STYLE[s].dot}
              hint={sevFilter === s ? 'Filter active - click to clear' : 'Click to filter'}
            />
          </button>
        ))}
      </div>

      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 p-4">
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(0); }}
              placeholder="Search description, agent, rule ID, IP…"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <select
            value={sevFilter}
            onChange={(e) => { setSevFilter(e.target.value as Severity | 'ALL'); setPage(0); }}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            aria-label="Severity filter"
          >
            <option value="ALL">All severities</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY_STYLE[s].label}</option>)}
          </select>
          <select
            value={agentFilter}
            onChange={(e) => { setAgentFilter(e.target.value); setPage(0); }}
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            aria-label="Agent filter"
          >
            <option value="ALL">All agents</option>
            {agents.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <span className="text-xs text-slate-500">{rows.length.toLocaleString()} of {all.length.toLocaleString()} alerts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-left text-sm">
            <thead className="bg-slate-950/60 text-xs text-slate-500">
              <tr>
                {sortHead('severity', 'Severity')}
                {sortHead('time', 'Time')}
                {sortHead('agent', 'Agent')}
                {sortHead('rule', 'Rule')}
                <th className="px-4 py-3 uppercase tracking-wide">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {visible.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => setOpen(a.id)}
                  className={clsx('cursor-pointer align-top hover:bg-slate-800/40', openId === a.id && 'bg-sky-500/5')}
                >
                  <td className="px-4 py-3"><SeverityBadge severity={severityFromLevel(a.level)} /></td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-400">{formatTime(a.timestamp)}</td>
                  <td className="px-4 py-3">
                    <p className="text-slate-200">{a.agentName}</p>
                    <p className="text-xs text-slate-500">ID {a.agentId} · {a.agentIp}</p>
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-mono text-xs text-slate-300">{a.ruleId}</p>
                    <p className="text-xs text-slate-500">Level {a.level}</p>
                  </td>
                  <td className="max-w-xl px-4 py-3 leading-6 text-slate-200">{a.description}</td>
                </tr>
              ))}
              {!visible.length && (
                <tr>
                  <td colSpan={5} className="p-6">
                    <EmptyState>{loading ? 'Loading Wazuh alerts…' : 'No alerts match the current filters.'}</EmptyState>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800 px-4 py-3 text-xs text-slate-500">
          <span>Page {safePage + 1} of {pages}</span>
          <div className="flex gap-2">
            <button disabled={safePage === 0} onClick={() => setPage(safePage - 1)} className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800 disabled:opacity-40" aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></button>
            <button disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)} className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800 disabled:opacity-40" aria-label="Next page"><ChevronRight className="h-4 w-4" /></button>
          </div>
        </div>
      </Panel>

      {openId && <AlertDrawer id={openId} fallback={all.find((a) => a.id === openId)} onClose={() => setOpen(null)} />}
    </div>
  );
}

function AlertDrawer({ id, fallback, onClose }: { id: string; fallback?: Alert; onClose: () => void }) {
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [error, setError] = useState('');
  const [showRaw, setShowRaw] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    setDetail(null);
    setError('');
    getJson<AlertDetail>(`/api/alerts/${encodeURIComponent(id)}`)
      .then((d) => alive && setDetail(d))
      .catch((e) => alive && setError(e instanceof Error ? e.message : 'Could not load alert detail'));
    return () => { alive = false; };
  }, [id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const agentId = detail?.agent.id ?? fallback?.agentId;
  const permitted = agentId === RESTRICTED_AGENT.id;
  const level = detail?.level ?? fallback?.level ?? 0;
  const mitre = detail?.rule.mitre;

  function askAi() {
    setPendingAiContext({ type: 'alert', alertId: id, label: detail?.rule.description ?? fallback?.description });
    navigate('/ai-analyst');
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-label="Alert details">
      <button className="absolute inset-0 bg-black/60" onClick={onClose} aria-label="Close details" />
      <aside className="relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-slate-800 bg-slate-950 shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-950/95 p-5 backdrop-blur">
          <div className="min-w-0">
            <SeverityBadge severity={severityFromLevel(level)} />
            <h2 className="mt-2 text-lg font-semibold leading-snug text-white">{detail?.rule.description ?? fallback?.description ?? 'Alert'}</h2>
            <p className="mt-1 text-xs text-slate-500">{formatTime(detail?.timestamp ?? fallback?.timestamp)}</p>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white" aria-label="Close"><X className="h-5 w-5" /></button>
        </div>

        <div className="space-y-6 p-5">
          <div>
            <button
              onClick={askAi}
              disabled={!permitted}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm font-medium text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
            >
              <Sparkles className="h-4 w-4" /> Explain with AI Analyst
            </button>
            {!permitted && (
              <p className="mt-2 text-xs text-slate-500">
                Live AI investigation is restricted to agent {RESTRICTED_AGENT.id} ({RESTRICTED_AGENT.name}).
              </p>
            )}
          </div>

          {error && <ErrorBanner title="Full event unavailable" message={`${error}. Showing list fields only.`} />}

          <dl className="grid grid-cols-2 gap-x-4 gap-y-4 text-sm">
            {([
              ['Rule ID', detail?.rule.id ?? fallback?.ruleId],
              ['Wazuh level', String(level)],
              ['Agent', detail?.agent.name ?? fallback?.agentName],
              ['Agent ID / IP', `${agentId ?? 'N/A'} · ${detail?.agent.ip ?? fallback?.agentIp ?? 'N/A'}`],
              ['Alert ID', id],
            ] as Array<[string, string | undefined]>).map(([k, v]) => (
              <div key={k} className={k === 'Alert ID' ? 'col-span-2' : ''}>
                <dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt>
                <dd className="mt-0.5 break-all text-slate-200">{v ?? 'N/A'}</dd>
              </div>
            ))}
          </dl>

          {detail?.rule.groups && detail.rule.groups.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {detail.rule.groups.map((g) => <span key={g} className="rounded-md bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{g}</span>)}
            </div>
          )}

          {mitre?.id && mitre.id.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Wazuh MITRE mapping</h3>
              <ul className="mt-2 space-y-1 text-sm text-slate-300">
                {mitre.id.map((t, i) => (
                  <li key={t}><span className="font-mono text-sky-300">{t}</span> {mitre.technique?.[i] ?? ''} <span className="text-slate-500">{mitre.tactic?.[i] ? `· ${mitre.tactic[i]}` : ''}</span></li>
                ))}
              </ul>
              <p className="mt-1 text-xs text-slate-500">A mapping does not prove the technique succeeded.</p>
            </div>
          )}

          {detail?.fullLog && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Full log</h3>
              <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-black p-3 text-xs text-slate-300">{detail.fullLog}</pre>
            </div>
          )}

          {detail && Object.keys(detail.data).length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Event data</h3>
              <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-slate-300">{JSON.stringify(detail.data, null, 2)}</pre>
            </div>
          )}

          {detail && (
            <div>
              <button onClick={() => setShowRaw(!showRaw)} className="text-sm text-sky-400 hover:text-sky-300">{showRaw ? 'Hide' : 'Show'} raw Wazuh document</button>
              {showRaw && <pre className="mt-2 max-h-96 overflow-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-slate-300">{JSON.stringify(detail.raw, null, 2)}</pre>}
            </div>
          )}
          {!detail && !error && <p className="text-sm text-slate-500">Loading full event…</p>}
        </div>
      </aside>
    </div>
  );
}
