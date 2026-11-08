
import { useEffect, useMemo, useState } from 'react';

const API_URL =
  import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';

type EvidenceAlert = {
  id: string;
  timestamp: string | null;
  ruleId: string;
  level: number;
  severity: string;
  description: string;
  agentName: string;
};

type Technique = {
  id: string;
  name: string;
  tactics: string[];
  eventCount: number;
  severityCounts: Record<string, number>;
  latestSeen: string | null;
  alerts: EvidenceAlert[];
};

type MitreResponse = {
  source: string;
  windowHours: number;
  alertCount: number;
  mappedEventCount: number;
  techniqueCount: number;
  techniques: Technique[];
};

function severityStyle(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-950 text-red-300 border-red-800';
    case 'high':
      return 'bg-orange-950 text-orange-300 border-orange-800';
    case 'medium':
      return 'bg-yellow-950 text-yellow-300 border-yellow-800';
    case 'low':
      return 'bg-blue-950 text-blue-300 border-blue-800';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-700';
  }
}

function formatTime(value: string | null) {
  return value ? new Date(value).toLocaleString() : 'N/A';
}

export default function MitreAttack() {
  const [data, setData] = useState<MitreResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [tacticFilter, setTacticFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  async function loadData() {
    try {
      setError('');
      const response = await fetch(`${API_URL}/api/mitre`);

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      setData(await response.json());
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to load MITRE data'
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => void loadData(), 30000);
    return () => window.clearInterval(timer);
  }, []);

  const tactics = useMemo(
    () =>
      Array.from(
        new Set((data?.techniques ?? []).flatMap((item) => item.tactics))
      ).sort(),
    [data]
  );

  const techniques = (data?.techniques ?? []).filter((item) => {
    const query = search.toLowerCase();

    const matchesSearch = [
      item.id,
      item.name,
      ...item.tactics,
      ...item.alerts.map((alert) => alert.description),
      ...item.alerts.map((alert) => alert.agentName),
    ].some((value) => value.toLowerCase().includes(query));

    const matchesTactic =
      tacticFilter === 'ALL' || item.tactics.includes(tacticFilter);

    const matchesSeverity =
      severityFilter === 'ALL' ||
      (item.severityCounts[severityFilter.toLowerCase()] ?? 0) > 0;

    return matchesSearch && matchesTactic && matchesSeverity;
  });

  const highSeverityEvents = (data?.techniques ?? []).reduce(
    (total, item) =>
      total +
      item.severityCounts.high +
      item.severityCounts.critical,
    0
  );

  if (loading) {
    return (
      <main className="p-8 text-slate-300">
        Loading MITRE ATT&CK data from Wazuh...
      </main>
    );
  }

  if (error) {
    return (
      <main className="p-8 text-slate-200">
        <h1 className="text-2xl font-bold">MITRE ATT&CK</h1>
        <p className="mt-3 text-red-400">{error}</p>
        <button
          onClick={() => {
            setLoading(true);
            void loadData();
          }}
          className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-white"
        >
          Retry
        </button>
      </main>
    );
  }

  return (
    <main className="space-y-6 p-6 text-slate-200 md:p-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">MITRE ATT&CK</h1>
          <p className="mt-1 text-sm text-slate-400">
            Explore techniques explicitly mapped in Wazuh security alerts.
          </p>
        </div>
        <span className="rounded-full border border-emerald-700 px-3 py-1 text-sm text-emerald-400">
          {data?.source ?? 'Wazuh Indexer'}
        </span>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Mapped techniques</p>
          <p className="mt-2 text-3xl font-bold">
            {data?.techniqueCount ?? 0}
          </p>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Mapped alert events</p>
          <p className="mt-2 text-3xl font-bold">
            {data?.mappedEventCount ?? 0}
          </p>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">High / Critical events</p>
          <p className="mt-2 text-3xl font-bold text-orange-300">
            {highSeverityEvents}
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
        <p className="text-sm text-slate-400">
          Showing the last {data?.windowHours ?? 24} hours. These are observed
          alert mappings, not proof that an adversary successfully used a
          technique.
        </p>
        <p className="mt-2 text-xs text-slate-500">
          Total Wazuh alerts checked: {data?.alertCount ?? 0}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search technique ID, name, tactic, or evidence..."
          className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none focus:border-blue-500"
        />

        <select
          value={tacticFilter}
          onChange={(event) => setTacticFilter(event.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm"
        >
          <option value="ALL">All tactics</option>
          {tactics.map((tactic) => (
            <option key={tactic} value={tactic}>
              {tactic}
            </option>
          ))}
        </select>

        <select
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm"
        >
          <option value="ALL">All severities</option>
          <option value="critical">Critical events</option>
          <option value="high">High events</option>
          <option value="medium">Medium events</option>
          <option value="low">Low events</option>
          <option value="info">Info events</option>
        </select>

        <button
          onClick={() => {
            setLoading(true);
            void loadData();
          }}
          className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
        >
          Refresh
        </button>
      </div>

      <div className="space-y-4">
        {techniques.map((technique) => {
          const expanded = selectedId === technique.id;

          return (
            <section
              key={technique.id}
              className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900"
            >
              <button
                onClick={() =>
                  setSelectedId(expanded ? null : technique.id)
                }
                className="w-full p-5 text-left transition hover:bg-slate-800/70"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="rounded-lg border border-blue-800 bg-blue-950 px-3 py-2 font-mono text-sm text-blue-300">
                      {technique.id}
                    </span>
                    <div>
                      <h2 className="font-semibold">{technique.name}</h2>
                      <p className="mt-1 text-sm text-slate-400">
                        {technique.tactics.join(', ')}
                      </p>
                    </div>
                  </div>

                  <span className="text-sm text-blue-300">
                    {expanded ? 'Hide evidence ↑' : 'View evidence ↓'}
                  </span>
                </div>

                <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
                  <div className="rounded-lg bg-slate-950 p-3">
                    <p className="text-xs text-slate-500">Mapped events</p>
                    <p className="mt-1 text-xl font-semibold">
                      {technique.eventCount}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-950 p-3">
                    <p className="text-xs text-slate-500">High / Critical</p>
                    <p className="mt-1 text-xl font-semibold text-orange-300">
                      {technique.severityCounts.high +
                        technique.severityCounts.critical}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-950 p-3">
                    <p className="text-xs text-slate-500">Latest mapped event</p>
                    <p className="mt-1 text-sm text-slate-200">
                      {formatTime(technique.latestSeen)}
                    </p>
                  </div>
                </div>
              </button>

              {expanded && (
                <div className="border-t border-slate-700 p-5">
                  <h3 className="mb-4 font-semibold">Alert evidence</h3>

                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[700px] text-left text-sm">
                      <thead className="text-slate-400">
                        <tr>
                          <th className="p-3">Time</th>
                          <th className="p-3">Severity</th>
                          <th className="p-3">Rule ID</th>
                          <th className="p-3">Agent</th>
                          <th className="p-3">Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {technique.alerts.map((alert) => (
                          <tr
                            key={alert.id}
                            className="border-t border-slate-800"
                          >
                            <td className="whitespace-nowrap p-3 text-slate-400">
                              {formatTime(alert.timestamp)}
                            </td>
                            <td className="p-3">
                              <span
                                className={`rounded border px-2 py-1 text-xs ${severityStyle(alert.severity)}`}
                              >
                                {alert.severity} ({alert.level})
                              </span>
                            </td>
                            <td className="p-3">{alert.ruleId}</td>
                            <td className="p-3">{alert.agentName}</td>
                            <td className="p-3">{alert.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <p className="mt-4 text-xs text-slate-500">
                    Evidence comes from Wazuh rule mappings. Validate each
                    event in context before concluding that this technique
                    occurred.
                  </p>
                </div>
              )}
            </section>
          );
        })}

        {techniques.length === 0 && (
          <div className="rounded-lg border border-slate-700 bg-slate-900 p-8 text-center text-slate-400">
            No mapped techniques match your filters. Some alerts may not
            contain MITRE metadata.
          </div>
        )}
      </div>
    </main>
  );
}
