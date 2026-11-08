
import { useEffect, useState } from 'react';

const API_URL =
  import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';

type StoryEvent = {
  id: string;
  timestamp: string;
  severity: string;
  ruleId: string;
  description: string;
  sourceIp: string;
  targetIp: string;
  agentName: string;
  mitreTechniques: string[];
};

type Story = {
  id: string;
  title: string;
  target: string;
  source: string;
  severity: string;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  riskScore: number;
  mitreTechniques: string[];
  events: StoryEvent[];
  explanation: string;
};

type StoryResponse = {
  source: string;
  windowHours: number;
  count: number;
  stories: Story[];
};

function severityStyle(severity: string) {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-950 text-red-300 border-red-800';
    case 'HIGH':
      return 'bg-orange-950 text-orange-300 border-orange-800';
    case 'MEDIUM':
      return 'bg-yellow-950 text-yellow-300 border-yellow-800';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-700';
  }
}

function formatTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function AttackStories() {
  const [data, setData] = useState<StoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  async function loadStories() {
    try {
      setError('');
      const response = await fetch(`${API_URL}/api/stories`);

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const result: StoryResponse = await response.json();
      setData(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Unable to load attack stories'
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadStories();
    const timer = window.setInterval(() => void loadStories(), 30000);
    return () => window.clearInterval(timer);
  }, []);

  const stories = (data?.stories ?? []).filter((story) => {
    const query = search.toLowerCase();

    const matchesSearch = [
      story.title,
      story.target,
      story.source,
      story.explanation,
      ...story.events.map((event) => event.description),
    ].some((value) => value.toLowerCase().includes(query));

    const matchesSeverity =
      severityFilter === 'ALL' ||
      story.severity.toUpperCase() === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const highSeverityCount = (data?.stories ?? []).filter(
    (story) =>
      story.severity === 'HIGH' || story.severity === 'CRITICAL'
  ).length;

  if (loading) {
    return (
      <main className="p-8 text-slate-300">
        Loading Attack Stories from Wazuh...
      </main>
    );
  }

  if (error) {
    return (
      <main className="p-8 text-slate-200">
        <h1 className="text-2xl font-bold">Attack Stories</h1>
        <p className="mt-3 text-red-400">{error}</p>
        <button
          onClick={() => {
            setLoading(true);
            void loadStories();
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
          <h1 className="text-2xl font-bold">Attack Stories</h1>
          <p className="mt-1 text-sm text-slate-400">
            Investigate related events and review their chronological evidence.
          </p>
        </div>
        <span className="rounded-full border border-emerald-700 px-3 py-1 text-sm text-emerald-400">
          {data?.source ?? 'Wazuh Indexer'}
        </span>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Stories found</p>
          <p className="mt-2 text-3xl font-bold">{data?.count ?? 0}</p>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">High / Critical stories</p>
          <p className="mt-2 text-3xl font-bold text-orange-300">
            {highSeverityCount}
          </p>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
          <p className="text-sm text-slate-400">Analysis window</p>
          <p className="mt-2 text-3xl font-bold">24 hours</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search target, event, or description..."
          className="min-w-64 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none focus:border-blue-500"
        />

        <select
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm"
        >
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <button
          onClick={() => {
            setLoading(true);
            void loadStories();
          }}
          className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium text-white hover:bg-blue-500"
        >
          Refresh
        </button>
      </div>

      <div className="space-y-4">
        {stories.map((story) => {
          const expanded = selectedId === story.id;

          return (
            <section
              key={story.id}
              className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900"
            >
              <button
                onClick={() =>
                  setSelectedId(expanded ? null : story.id)
                }
                className="w-full p-5 text-left transition hover:bg-slate-800/70"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-lg font-semibold">
                        {story.title}
                      </h2>
                      <span
                        className={`rounded border px-2 py-1 text-xs font-semibold ${severityStyle(story.severity)}`}
                      >
                        {story.severity}
                      </span>
                    </div>

                    <p className="mt-2 text-sm text-slate-400">
                      Target: <span className="text-slate-200">{story.target}</span>
                      {' · '}
                      {story.eventCount} event
                      {story.eventCount === 1 ? '' : 's'}
                    </p>
                  </div>

                  <span className="text-sm text-blue-300">
                    {expanded ? 'Hide timeline ↑' : 'View timeline ↓'}
                  </span>
                </div>

                <p className="mt-3 text-sm text-slate-300">
                  {story.explanation}
                </p>

                <div className="mt-4 grid gap-3 text-xs text-slate-400 sm:grid-cols-3">
                  <div>
                    <p>First seen</p>
                    <p className="mt-1 text-slate-200">
                      {formatTime(story.firstSeen)}
                    </p>
                  </div>
                  <div>
                    <p>Last seen</p>
                    <p className="mt-1 text-slate-200">
                      {formatTime(story.lastSeen)}
                    </p>
                  </div>
                  <div>
                    <p>Risk indicator</p>
                    <p className="mt-1 text-slate-200">
                      {story.riskScore}/100
                    </p>
                  </div>
                </div>
              </button>

              {expanded && (
                <div className="border-t border-slate-700 p-5">
                  <h3 className="mb-4 font-semibold">Event timeline</h3>

                  <div className="space-y-4">
                    {story.events.map((event, index) => (
                      <div
                        key={`${event.id}-${index}`}
                        className="relative border-l-2 border-slate-700 pb-2 pl-5"
                      >
                        <span className="absolute -left-[5px] top-1 h-2 w-2 rounded-full bg-blue-400" />

                        <p className="text-xs text-slate-400">
                          {formatTime(event.timestamp)}
                          {' · '}Rule {event.ruleId}
                        </p>

                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded border px-2 py-1 text-xs ${severityStyle(event.severity)}`}
                          >
                            {event.severity}
                          </span>
                          <span className="font-medium">
                            {event.agentName}
                          </span>
                        </div>

                        <p className="mt-2 text-sm text-slate-200">
                          {event.description}
                        </p>

                        <p className="mt-2 text-xs text-slate-400">
                          Source: {event.sourceIp}
                          {' · '}Target: {event.targetIp}
                        </p>

                        {event.mitreTechniques.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-2">
                            {event.mitreTechniques.map((technique) => (
                              <span
                                key={technique}
                                className="rounded bg-slate-800 px-2 py-1 text-xs text-blue-300"
                              >
                                MITRE {technique}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  <p className="mt-4 rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs text-slate-400">
                    Investigation note: correlation indicates related activity,
                    not confirmed compromise. Verify the events and surrounding
                    endpoint context before deciding whether this is a true
                    positive.
                  </p>
                </div>
              )}
            </section>
          );
        })}

        {stories.length === 0 && (
          <div className="rounded-lg border border-slate-700 bg-slate-900 p-8 text-center text-slate-400">
            No stories match your search or severity filter.
          </div>
        )}
      </div>
    </main>
  );
}
