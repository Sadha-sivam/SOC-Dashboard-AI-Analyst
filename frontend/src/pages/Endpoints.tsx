import { useEffect, useState } from 'react';

const API_URL =
  import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';

type Endpoint = {
  id: string;
  name: string;
  ip: string;
  status: string;
  operatingSystem: string;
  osVersion: string;
  lastKeepAlive: string | null;
  nodeName: string;
};

type EndpointResponse = {
  source: string;
  count: number;
  summary: {
    active: number;
    disconnected: number;
    other: number;
  };
  endpoints: Endpoint[];
};

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toLowerCase();

  const style =
    normalized === 'active'
      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
      : normalized === 'disconnected'
      ? 'bg-red-950 text-red-400 border-red-800'
      : 'bg-slate-800 text-slate-300 border-slate-700';

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold ${style}`}
    >
      <span className="h-2 w-2 rounded-full bg-current" />
      {status}
    </span>
  );
}

function formatLastSeen(value: string | null, status: string) {
  if (status.toLowerCase() === 'active') {
    return 'Connected';
  }

  if (!value || value.startsWith('9999-')) {
    return 'Not available';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Not available';
  }

  return date.toLocaleString();
}

export default function Endpoints() {
  const [data, setData] = useState<EndpointResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  async function loadEndpoints() {
    try {
      setError('');

      const response = await fetch(`${API_URL}/api/agents`);

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const result: EndpointResponse = await response.json();
      setData(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to load endpoints'
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadEndpoints();

    const timer = window.setInterval(() => {
      void loadEndpoints();
    }, 15000);

    return () => window.clearInterval(timer);
  }, []);

  const endpoints = (data?.endpoints ?? []).filter((endpoint) => {
    const query = search.toLowerCase();

    const matchesSearch = [
      endpoint.name,
      endpoint.id,
      endpoint.ip,
      endpoint.operatingSystem,
      endpoint.status,
    ].some((value) => value.toLowerCase().includes(query));

    const matchesStatus =
      statusFilter === 'all' ||
      endpoint.status.toLowerCase() === statusFilter;

    return matchesSearch && matchesStatus;
  });

  if (loading) {
    return (
      <main className="p-8 text-slate-300">
        Loading monitored endpoints...
      </main>
    );
  }

  if (error) {
    return (
      <main className="p-8 text-slate-200">
        <h1 className="text-2xl font-bold">Endpoints</h1>
        <p className="mt-3 text-red-400">
          Could not load Wazuh agents: {error}
        </p>
        <button
          onClick={() => {
            setLoading(true);
            void loadEndpoints();
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
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Endpoint Monitoring</h1>
          <p className="mt-2 text-sm text-slate-400">
            Monitor registered systems and their Wazuh agent status.
          </p>
        </div>

        <span className="rounded-full border border-emerald-800 bg-emerald-950 px-3 py-2 text-sm text-emerald-400">
          Live API · Wazuh
        </span>
      </header>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Registered endpoints</p>
          <p className="mt-3 text-3xl font-bold">{data?.count ?? 0}</p>
          <p className="mt-2 text-xs text-slate-500">
            Systems registered with Wazuh
          </p>
        </div>

        <div className="rounded-xl border border-emerald-900 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Active</p>
          <p className="mt-3 text-3xl font-bold text-emerald-400">
            {data?.summary.active ?? 0}
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Currently connected agents
          </p>
        </div>

        <div className="rounded-xl border border-red-900 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Disconnected</p>
          <p className="mt-3 text-3xl font-bold text-red-400">
            {data?.summary.disconnected ?? 0}
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Agents requiring connectivity checks
          </p>
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Other statuses</p>
          <p className="mt-3 text-3xl font-bold">
            {data?.summary.other ?? 0}
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Pending or other reported states
          </p>
        </div>
      </section>

      <section className="rounded-xl border border-slate-700 bg-slate-900/60">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 p-5">
          <div>
            <h2 className="font-semibold">Monitored systems</h2>
            <p className="mt-1 text-sm text-slate-400">
              Agent inventory from the Wazuh API
            </p>
          </div>

          <button
            onClick={() => {
              setLoading(true);
              void loadEndpoints();
            }}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
          >
            Refresh
          </button>
        </div>

        <div className="flex flex-wrap gap-3 p-5">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search name, IP, OS or agent ID..."
            className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm outline-none focus:border-blue-500"
          />

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm"
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="disconnected">Disconnected</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="bg-slate-950/70 text-slate-400">
              <tr>
                <th className="p-4">Endpoint</th>
                <th className="p-4">IP address</th>
                <th className="p-4">Operating system</th>
                <th className="p-4">Status</th>
                <th className="p-4">Last seen</th>
              </tr>
            </thead>

            <tbody>
              {endpoints.map((endpoint) => (
                <tr
                  key={endpoint.id}
                  className="border-t border-slate-800 hover:bg-slate-800/40"
                >
                  <td className="p-4">
                    <p className="font-medium">{endpoint.name}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      Agent ID: {endpoint.id}
                    </p>
                  </td>

                  <td className="p-4 font-mono text-slate-300">
                    {endpoint.ip}
                  </td>

                  <td className="p-4">
                    <p>{endpoint.operatingSystem}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {endpoint.osVersion}
                    </p>
                  </td>

                  <td className="p-4">
                    <StatusBadge status={endpoint.status} />
                  </td>

                  <td className="p-4 text-slate-400">
                    {formatLastSeen(
                      endpoint.lastKeepAlive,
                      endpoint.status
                    )}
                  </td>
                </tr>
              ))}

              {endpoints.length === 0 && (
                <tr>
                  <td
                    colSpan={5}
                    className="p-8 text-center text-slate-400"
                  >
                    No endpoints match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="border-t border-slate-800 p-4 text-xs text-slate-500">
          Showing {endpoints.length} of {data?.count ?? 0} endpoints.
          Refreshes every 15 seconds.
        </div>
      </section>
    </main>
  );
}
