import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { getJson, formatTime } from '../lib/api';
import { EmptyState, ErrorBanner, PageHeader, Panel, RefreshButton, SeverityBadge } from '../components/ui';

type Story = {
  id: string;
  title: string;
  target: string;
  source: string;
  severity: string;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
};

export default function IncidentList() {
  const navigate = useNavigate();
  const [stories, setStories] = useState<Story[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await getJson<{ source: string; stories?: Story[] }>('/api/stories');
      if (data.source !== 'Wazuh Indexer') throw new Error('Unexpected data source; expected Wazuh Indexer.');
      setStories(data.stories || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load Wazuh stories.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigations"
        subtitle="Wazuh events grouped by endpoint and five-minute windows (last 24 hours). Grouping does not confirm an attack."
        actions={<RefreshButton onClick={() => void load()} loading={loading} />}
      />

      {error && <ErrorBanner title="Could not load live investigation data" message={error} onRetry={() => void load()} />}

      <Panel bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="bg-slate-950/60 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-5 py-3">Group</th>
                <th className="px-5 py-3">Endpoint</th>
                <th className="px-5 py-3">Events</th>
                <th className="px-5 py-3">Severity</th>
                <th className="px-5 py-3">Last seen</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {stories.map((s) => (
                <tr key={s.id} onClick={() => navigate(`/incidents/${s.id}`)} className="cursor-pointer hover:bg-slate-800/40">
                  <td className="px-5 py-3.5 font-mono text-xs text-slate-400">{s.id}</td>
                  <td className="px-5 py-3.5">
                    <p className="font-medium text-slate-100">{s.title}</p>
                    <p className="mt-0.5 text-xs text-slate-500">Target {s.target} · Source {s.source || 'Unknown'}</p>
                  </td>
                  <td className="px-5 py-3.5 tabular-nums text-slate-200">{s.eventCount}</td>
                  <td className="px-5 py-3.5"><SeverityBadge severity={s.severity} /></td>
                  <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-400">{s.lastSeen ? formatTime(s.lastSeen) : 'Unknown'}</td>
                  <td className="px-5 py-3.5 text-right text-sky-400"><span className="inline-flex items-center gap-1 text-sm">Investigate <ArrowRight className="h-4 w-4" /></span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {loading && <p className="p-5 text-sm text-slate-400">Loading live Wazuh story groups…</p>}
        {!loading && !error && stories.length === 0 && <div className="p-5"><EmptyState>No story groups were returned for the last 24 hours.</EmptyState></div>}
      </Panel>

      <p className="text-xs text-slate-500">Severity is derived from Wazuh rule levels and is not a probability of compromise. All groups require analyst validation.</p>
    </div>
  );
}
