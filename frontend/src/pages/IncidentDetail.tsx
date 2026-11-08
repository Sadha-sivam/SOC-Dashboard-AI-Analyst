import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, ChevronDown, ChevronUp, Sparkles } from 'lucide-react';
import { getJson, formatTime } from '../lib/api';
import { SEVERITY_STYLE, asSeverity, severityFromLevel } from '../lib/severity';
import { RESTRICTED_AGENT, setPendingAiContext } from '../lib/aiContext';
import { EmptyState, ErrorBanner, PageHeader, Panel, RefreshButton, SeverityBadge, StatCard } from '../components/ui';

type EvidenceEvent = {
  id: string;
  timestamp: string;
  severity: string;
  ruleId: string;
  description: string;
  sourceIp?: string;
  targetIp?: string;
  agentName?: string;
  agentId?: string;
  mitreTechniques?: string[];
  ruleLevel?: number;
  rawEvent?: Record<string, unknown>;
};

type StoryDetail = {
  id: string;
  title: string;
  target: string;
  source: string;
  severity: string;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  events: EvidenceEvent[];
};

const STATUSES = [
  ['PENDING', 'Pending review'],
  ['INVESTIGATING', 'Investigating'],
  ['TRUE_POSITIVE', 'True positive'],
  ['FALSE_POSITIVE', 'False positive'],
  ['INCONCLUSIVE', 'Inconclusive'],
] as const;

type Review = { status: string; notes: string; updatedAt?: string };

/** Analyst review is stored in this browser only; the backend does not persist verdicts. */
function reviewKey(s: StoryDetail) {
  return `soc.review.${s.target}.${s.firstSeen}`;
}
function loadReview(s: StoryDetail): Review {
  try {
    const raw = localStorage.getItem(reviewKey(s));
    if (raw) return JSON.parse(raw) as Review;
  } catch {
    /* ignore */
  }
  return { status: 'PENDING', notes: '' };
}

export default function IncidentDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [story, setStory] = useState<StoryDetail | null>(null);
  const [note, setNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [review, setReview] = useState<Review>({ status: 'PENDING', notes: '' });

  const loadEvidence = useCallback(async () => {
    if (!id) {
      setError('Missing story ID in the URL.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const data = await getJson<{ source: string; story?: StoryDetail; correlationNote?: string }>(`/api/stories/${encodeURIComponent(id)}`);
      if (data.source !== 'Wazuh Indexer' || !data.story) throw new Error('Response did not contain a Wazuh investigation story.');
      setStory(data.story);
      setReview(loadReview(data.story));
      setNote(data.correlationNote || 'Review the original events before drawing a conclusion.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load investigation evidence.');
      setStory(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void loadEvidence();
  }, [loadEvidence]);

  function updateReview(patch: Partial<Review>) {
    if (!story) return;
    const next = { ...review, ...patch, updatedAt: new Date().toISOString() };
    setReview(next);
    try {
      localStorage.setItem(reviewKey(story), JSON.stringify(next));
    } catch {
      /* storage unavailable: review stays in memory only */
    }
  }

  const events = useMemo(
    () => [...(story?.events ?? [])].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [story],
  );
  const permittedIds = events.filter((e) => e.agentId === RESTRICTED_AGENT.id).map((e) => e.id);
  const techniques = useMemo(() => [...new Set(events.flatMap((e) => e.mitreTechniques ?? []))], [events]);
  const ruleSummary = useMemo(() => {
    const m = new Map<string, { description: string; count: number }>();
    for (const e of events) {
      const k = `${e.ruleId}`;
      m.set(k, { description: e.description, count: (m.get(k)?.count ?? 0) + 1 });
    }
    return [...m.entries()].sort((a, b) => b[1].count - a[1].count);
  }, [events]);

  function askAi() {
    if (!story) return;
    setPendingAiContext({ type: 'investigation', alertIds: permittedIds.slice(0, 200), label: story.title });
    navigate('/ai-analyst');
  }

  if (loading) return <div className="p-6 text-slate-300">Loading evidence from Wazuh Indexer…</div>;

  if (error || !story) {
    return (
      <div className="space-y-4">
        <Link to="/incidents" className="inline-flex items-center gap-1 text-sm text-sky-400 hover:text-sky-300"><ArrowLeft className="h-4 w-4" /> Back to investigations</Link>
        <ErrorBanner title="Could not load investigation" message={error || 'No story data was returned.'} onRetry={() => void loadEvidence()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Link to="/incidents" className="inline-flex items-center gap-1 text-sm text-sky-400 hover:text-sky-300"><ArrowLeft className="h-4 w-4" /> Back to investigations</Link>

      <PageHeader
        title={story.title}
        subtitle={`${story.id} · Source: Wazuh Indexer · Last 24 hours · ${formatTime(story.firstSeen)} → ${formatTime(story.lastSeen)}`}
        actions={
          <>
            <button
              onClick={askAi}
              disabled={permittedIds.length === 0}
              title={permittedIds.length === 0 ? `AI investigation is restricted to agent ${RESTRICTED_AGENT.id} (${RESTRICTED_AGENT.name})` : undefined}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm font-medium text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
            >
              <Sparkles className="h-4 w-4" /> Analyse with AI
            </button>
            <RefreshButton onClick={() => void loadEvidence()} loading={loading} />
          </>
        }
      />
      {permittedIds.length === 0 && (
        <p className="-mt-3 text-xs text-slate-500">
          AI analysis is available only for agent {RESTRICTED_AGENT.id} ({RESTRICTED_AGENT.name}); this group has no events from that agent.
        </p>
      )}

      <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Events" value={story.eventCount} bar="bg-slate-500" />
        <StatCard label="Highest severity" value={SEVERITY_STYLE[asSeverity(story.severity)].label} bar={SEVERITY_STYLE[asSeverity(story.severity)].dot} />
        <StatCard label="Target / endpoint" value={<span className="break-all text-xl">{story.target || 'Unknown'}</span>} bar="bg-sky-500" />
        <StatCard label="Source IP" value={<span className="break-all text-xl">{story.source || 'Unknown'}</span>} bar="bg-sky-500" />
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <Panel title="Correlation note">
            <p className="text-sm leading-6 text-slate-300">{note}</p>
            <p className="mt-2 text-xs text-slate-500">Events are grouped by endpoint and a five-minute window. This is a triage aid, not a confirmed incident verdict.</p>
          </Panel>

          <Panel title="Event timeline" description="Original alert descriptions and timestamps from the Wazuh Indexer, oldest first">
            <ol className="relative ml-2 space-y-5 border-l border-slate-800 pl-6">
              {events.map((e) => {
                const sev = asSeverity(e.severity ?? severityFromLevel(e.ruleLevel ?? 0));
                return (
                  <li key={e.id} className="relative">
                    <span className={`absolute -left-[31px] top-1.5 h-3 w-3 rounded-full ring-4 ring-slate-900 ${SEVERITY_STYLE[sev].dot}`} />
                    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <time className="font-mono text-xs text-slate-400">{formatTime(e.timestamp)}</time>
                        <span className="flex items-center gap-2"><SeverityBadge severity={sev} /><span className="text-xs text-slate-500">level {e.ruleLevel ?? 'N/A'}</span></span>
                      </div>
                      <h3 className="mt-2 text-sm font-medium text-white">{e.description}</h3>
                      <dl className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                        <div><dt className="text-slate-500">Rule ID</dt><dd className="text-slate-300">{e.ruleId}</dd></div>
                        <div><dt className="text-slate-500">Agent</dt><dd className="text-slate-300">{e.agentName || 'Unknown'} ({e.agentId || 'N/A'})</dd></div>
                        <div><dt className="text-slate-500">Source IP</dt><dd className="text-slate-300">{e.sourceIp || 'Not present in normalized fields'}</dd></div>
                        <div><dt className="text-slate-500">Target IP</dt><dd className="text-slate-300">{e.targetIp || 'Not present in normalized fields'}</dd></div>
                      </dl>
                      {e.mitreTechniques && e.mitreTechniques.length > 0 && (
                        <p className="mt-2 text-xs text-slate-400">Wazuh MITRE mapping: <span className="font-mono text-sky-300">{e.mitreTechniques.join(', ')}</span></p>
                      )}
                      <button onClick={() => setExpanded(expanded === e.id ? null : e.id)} className="mt-3 inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300">
                        {expanded === e.id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                        {expanded === e.id ? 'Hide raw event' : 'Inspect raw Wazuh event'}
                      </button>
                      {expanded === e.id && (
                        <pre className="mt-3 max-h-96 overflow-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-slate-300">{JSON.stringify(e.rawEvent ?? {}, null, 2)}</pre>
                      )}
                    </div>
                  </li>
                );
              })}
              {events.length === 0 && <EmptyState>No event records were returned for this group.</EmptyState>}
            </ol>
          </Panel>
        </div>

        <div className="space-y-6">
          <Panel title="Analyst review" description="Saved in this browser only - the backend does not store verdicts">
            <label className="text-xs font-medium uppercase tracking-wide text-slate-400" htmlFor="status">Investigation status</label>
            <select id="status" value={review.status} onChange={(e) => updateReview({ status: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
              {STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
            <label className="mt-4 block text-xs font-medium uppercase tracking-wide text-slate-400" htmlFor="notes">Notes and conclusion</label>
            <textarea id="notes" value={review.notes} onChange={(e) => updateReview({ notes: e.target.value })} rows={6} placeholder="Supporting and contradicting evidence, conclusion…" className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none" />
            {review.updatedAt && <p className="mt-2 text-xs text-slate-500">Saved {formatTime(review.updatedAt)}</p>}
          </Panel>

          <Panel title="Related detections" description="Rules triggered in this group">
            <ul className="space-y-2 text-sm">
              {ruleSummary.map(([rule, v]) => (
                <li key={rule} className="flex items-start justify-between gap-3">
                  <span className="text-slate-300"><span className="font-mono text-xs text-slate-500">{rule}</span> {v.description}</span>
                  <span className="shrink-0 rounded-md bg-slate-800 px-2 py-0.5 text-xs tabular-nums text-slate-300">×{v.count}</span>
                </li>
              ))}
            </ul>
            {techniques.length > 0 && (
              <div className="mt-4 border-t border-slate-800 pt-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">Wazuh MITRE IDs</p>
                <div className="mt-2 flex flex-wrap gap-1.5">{techniques.map((t) => <span key={t} className="rounded-md border border-slate-700 px-2 py-0.5 font-mono text-xs text-sky-300">{t}</span>)}</div>
              </div>
            )}
          </Panel>

          <Panel title="Review checklist">
            <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
              <li>Validate rule ID and timestamp against the raw event.</li>
              <li>Check whether source, target and account are expected.</li>
              <li>Correlate with authentication, process and network evidence.</li>
              <li>Validate any MITRE mapping against the underlying event.</li>
              <li>Record supporting and contradicting evidence before deciding.</li>
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
