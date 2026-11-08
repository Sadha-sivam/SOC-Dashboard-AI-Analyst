import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Eye,
  Loader2,
  MessageSquare,
  PanelRight,
  Plus,
  Send,
  ShieldCheck,
  Sparkles,
  Trash2,
  User,
  X,
} from 'lucide-react';
import clsx from 'clsx';
import { API_URL, formatTime, getJson } from '../lib/api';
import { RESTRICTED_AGENT, takePendingAiContext, type AiContext } from '../lib/aiContext';
import { Markdown } from '../lib/markdown';
import {
  loadConversations,
  newConversation,
  saveConversations,
  uid,
  type ChatMessage,
  type Conversation,
} from '../lib/chatStore';
import { SeverityBadge } from '../components/ui';

type AiStatus = {
  enabled: boolean;
  configured: boolean;
  provider: string;
  model: string;
  message: string;
  restrictedAgent: { id: string; name: string };
  limits: { rateLimitPerMinute: number; maxEvidenceAlerts: number; evidenceWindowHours: number };
};

type Triage = {
  alertCount: number;
  highSeverityCount: number;
  riskScore: number;
  techniqueCount: number;
  summary: string;
  generatedAt: string;
  findings: Array<{ title: string; detail: string; severity: string }>;
};

const SUGGESTIONS: Array<{ label: string; prompt: string }> = [
  { label: 'Explain this security alert', prompt: 'Explain this security alert: what does the rule detect, what does the evidence show, and why might it matter?' },
  { label: 'What happened in this investigation?', prompt: 'What happened in this investigation? Provide the full investigation summary.' },
  { label: 'Identify suspicious behaviour', prompt: 'Identify suspicious behaviour in the evidence. Separate observed facts from hypotheses.' },
  { label: 'Build an attack timeline', prompt: 'Build an attack timeline from the evidence, using only the timestamps and events present.' },
  { label: 'Why might this be a false positive?', prompt: 'Explain why this activity might be a false positive, and what evidence would confirm or rule that out.' },
  { label: 'What should I investigate next?', prompt: 'What should the SOC analyst investigate next? Give prioritised, verifiable steps.' },
];

function contextLabel(c: AiContext): string {
  if (c.type === 'alert') return c.label ? `Alert: ${c.label}` : 'Selected alert';
  if (c.type === 'investigation') return c.label ? `Investigation: ${c.label}` : 'Selected investigation';
  return `Latest activity on ${RESTRICTED_AGENT.name} (24h)`;
}

function titleFrom(text: string): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > 48 ? `${t.slice(0, 48)}…` : t || 'New conversation';
}

export default function AIAnalyst() {
  const [conversations, setConversations] = useState<Conversation[]>(() => loadConversations());
  const [activeId, setActiveId] = useState<string | null>(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [statusError, setStatusError] = useState('');
  const [showList, setShowList] = useState(false);
  const [showSide, setShowSide] = useState(false);
  const [preview, setPreview] = useState<{ loading: boolean; data?: unknown; error?: string } | null>(null);
  const [triage, setTriage] = useState<Triage | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  const initialised = useRef(false);

  const active = useMemo(() => conversations.find((c) => c.id === activeId) ?? null, [conversations, activeId]);

  // Persist
  useEffect(() => {
    saveConversations(conversations);
  }, [conversations]);

  // Initial conversation: honour a context handed over from the Alert Queue / Investigation page.
  useEffect(() => {
    if (initialised.current) return;
    initialised.current = true;
    const pending = takePendingAiContext();
    if (pending) {
      const conv = newConversation(pending);
      setConversations((prev) => [conv, ...prev]);
      setActiveId(conv.id);
    } else {
      const existing = loadConversations();
      if (existing.length) setActiveId(existing[0].id);
      else {
        const conv = newConversation();
        setConversations([conv]);
        setActiveId(conv.id);
      }
    }
  }, []);

  useEffect(() => {
    getJson<AiStatus>('/api/ai/status')
      .then(setStatus)
      .catch((e) => setStatusError(e instanceof Error ? e.message : 'Unable to read AI status'));
    // Existing local rule-based triage endpoint (unchanged) is shown in the side panel.
    getJson<Triage>('/api/ai-analyst').then(setTriage).catch(() => setTriage(null));
    return () => abortRef.current?.abort();
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [active?.messages.length, loading]);

  const update = useCallback((id: string, fn: (c: Conversation) => Conversation) => {
    setConversations((prev) => prev.map((c) => (c.id === id ? fn(c) : c)));
  }, []);

  function startNew() {
    abortRef.current?.abort();
    setLoading(false);
    const conv = newConversation();
    setConversations((prev) => [conv, ...prev]);
    setActiveId(conv.id);
    setInput('');
    setShowList(false);
  }

  function remove(id: string) {
    setConversations((prev) => {
      const next = prev.filter((c) => c.id !== id);
      if (id === activeId) {
        if (next.length) setActiveId(next[0].id);
        else {
          const conv = newConversation();
          setActiveId(conv.id);
          return [conv];
        }
      }
      return next;
    });
  }

  async function ask(text: string, opts: { conv?: Conversation; retry?: boolean } = {}) {
    const conv = opts.conv ?? active;
    const content = text.trim();
    if (!conv || !content || loading) return;

    const base = opts.retry ? conv.messages.filter((m) => !m.error) : conv.messages.filter((m) => !m.error);
    const userMsg: ChatMessage = { id: uid(), role: 'user', content, createdAt: new Date().toISOString() };
    const history = opts.retry ? base : [...base, userMsg];

    update(conv.id, (c) => ({
      ...c,
      title: c.messages.length === 0 ? titleFrom(content) : c.title,
      updatedAt: new Date().toISOString(),
      messages: opts.retry ? base : [...base, userMsg],
    }));
    setInput('');
    setLoading(true);

    const controller = new AbortController();
    abortRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 120_000);

    try {
      const res = await fetch(`${API_URL}/api/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          messages: history.map((m) => ({ role: m.role, content: m.content })),
          context: conv.context.type === 'recent' ? { type: 'recent' } : conv.context,
        }),
      });
      let body: any = null;
      try {
        body = await res.json();
      } catch {
        /* non-JSON */
      }
      if (!res.ok) {
        const e = body?.error;
        throw Object.assign(new Error(typeof e === 'string' ? e : e?.message || `Request failed (HTTP ${res.status})`), {
          code: typeof e === 'object' ? e?.code : 'HTTP_ERROR',
          retryAfterSeconds: e?.retryAfterSeconds,
        });
      }
      const reply: ChatMessage = {
        id: uid(),
        role: 'assistant',
        content: String(body.reply ?? ''),
        createdAt: body.generatedAt ?? new Date().toISOString(),
        meta: {
          model: body.model,
          alertsConsidered: body.evidence?.alertsConsidered,
          alertsIncluded: body.evidence?.alertsIncluded,
          masked: body.evidence?.masking?.total,
          totalTokens: body.usage?.totalTokens,
        },
      };
      update(conv.id, (c) => ({ ...c, updatedAt: new Date().toISOString(), messages: [...c.messages, reply] }));
    } catch (e: any) {
      if (controller.signal.aborted && abortRef.current !== controller) return; // superseded by "new conversation"
      const aborted = controller.signal.aborted;
      const err: ChatMessage = {
        id: uid(),
        role: 'assistant',
        content: '',
        createdAt: new Date().toISOString(),
        error: {
          code: aborted ? 'CLIENT_TIMEOUT' : e?.code ?? 'NETWORK',
          message: aborted
            ? 'The request took too long and was cancelled.'
            : e instanceof TypeError
              ? 'Could not reach the backend. Is it running?'
              : e?.message || 'Unexpected error.',
          retryAfterSeconds: e?.retryAfterSeconds,
        },
      };
      update(conv.id, (c) => ({ ...c, messages: [...c.messages, err] }));
    } finally {
      window.clearTimeout(timeout);
      setLoading(false);
    }
  }

  function retryLast() {
    if (!active) return;
    const lastUser = [...active.messages].reverse().find((m) => m.role === 'user');
    if (lastUser) void ask(lastUser.content, { retry: true });
  }

  async function showPreview() {
    if (!active) return;
    setPreview({ loading: true });
    try {
      const res = await fetch(`${API_URL}/api/ai/preview`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: active.context }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.error?.message || `HTTP ${res.status}`);
      setPreview({ loading: false, data: body });
    } catch (e) {
      setPreview({ loading: false, error: e instanceof Error ? e.message : 'Preview failed' });
    }
  }

  const notReady = status && (!status.enabled || !status.configured);
  const messages = active?.messages ?? [];

  return (
    <div className="flex h-full min-h-0">
      {/* Conversation list */}
      <aside
        className={clsx(
          'z-30 w-72 shrink-0 flex-col border-r border-slate-800 bg-slate-950',
          showList ? 'fixed inset-y-0 left-0 flex md:static' : 'hidden md:flex',
        )}
      >
        <div className="p-3">
          <button
            onClick={startNew}
            className="flex w-full items-center gap-2 rounded-lg border border-slate-700 px-3 py-2.5 text-sm font-medium text-slate-100 hover:bg-slate-900"
          >
            <Plus className="h-4 w-4" /> New conversation
          </button>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3" aria-label="Conversations">
          {conversations.map((c) => (
            <div
              key={c.id}
              className={clsx(
                'group flex items-center gap-1 rounded-lg pr-1 text-sm',
                c.id === activeId ? 'bg-slate-800/80 text-white' : 'text-slate-400 hover:bg-slate-900',
              )}
            >
              <button
                onClick={() => {
                  setActiveId(c.id);
                  setShowList(false);
                }}
                className="flex min-w-0 flex-1 items-center gap-2 px-3 py-2 text-left"
              >
                <MessageSquare className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{c.title}</span>
              </button>
              <button
                onClick={() => remove(c.id)}
                className="rounded p-1.5 text-slate-500 opacity-0 hover:bg-slate-700 hover:text-red-300 focus:opacity-100 group-hover:opacity-100"
                aria-label={`Delete conversation ${c.title}`}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </nav>
        <p className="border-t border-slate-800 p-3 text-[11px] leading-4 text-slate-500">
          Conversations are stored in this browser only. Evidence is re-collected from Wazuh for every question.
        </p>
      </aside>
      {showList && <button className="fixed inset-0 z-20 bg-black/60 md:hidden" onClick={() => setShowList(false)} aria-label="Close conversations" />}

      {/* Chat column */}
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-4 py-3">
          <button onClick={() => setShowList(true)} className="rounded-md border border-slate-700 p-2 text-slate-300 md:hidden" aria-label="Show conversations">
            <MessageSquare className="h-4 w-4" />
          </button>
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-sky-400" />
            <h1 className="text-base font-semibold text-white">AI Analyst</h1>
          </div>
          {active && (
            <span className="inline-flex max-w-xs items-center gap-1.5 truncate rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300" title={contextLabel(active.context)}>
              <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span className="truncate">{contextLabel(active.context)}</span>
            </span>
          )}
          <div className="ml-auto flex items-center gap-2">
            <StatusPill status={status} error={statusError} />
            <button onClick={() => void showPreview()} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-900" title="See exactly what evidence would be sent (masked)" aria-label="Preview evidence sent to AI provider">
              <Eye className="h-3.5 w-3.5" /> Evidence
            </button>
            <button onClick={() => setShowSide(!showSide)} className={clsx('hidden rounded-lg border border-slate-700 p-1.5 text-slate-300 hover:bg-slate-900 xl:block', showSide && 'bg-slate-900')} aria-label="Toggle local triage panel" title="Local rule-based triage">
              <PanelRight className="h-4 w-4" />
            </button>
          </div>
        </header>

        {notReady && (
          <div role="status" className="flex items-start gap-3 border-b border-amber-500/20 bg-amber-500/5 px-4 py-3 text-sm text-amber-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <p>
              <strong className="font-semibold">AI configuration required.</strong>{' '}
              {!status!.enabled ? 'The AI Analyst is disabled (AI_ENABLED=false).' : 'Set OPENROUTER_API_KEY in backend/.env and restart the backend.'}{' '}
              The rest of the dashboard is unaffected; you can still preview the evidence that would be sent.
            </p>
          </div>
        )}

        {/* Messages */}
        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-3xl px-4 py-6">
            {messages.length === 0 ? (
              <EmptyChat onPick={(p) => void ask(p)} disabled={loading || !!notReady} context={active ? contextLabel(active.context) : ''} />
            ) : (
              <ul className="space-y-6">
                {messages.map((m, idx) => (
                  <MessageRow key={m.id} m={m} isLast={idx === messages.length - 1} onRetry={retryLast} disabled={loading} />
                ))}
                {loading && (
                  <li className="flex gap-3" aria-live="polite">
                    <Avatar role="assistant" />
                    <div className="flex items-center gap-2 pt-1 text-sm text-slate-400">
                      <Loader2 className="h-4 w-4 animate-spin" /> Collecting evidence and analysing…
                    </div>
                  </li>
                )}
              </ul>
            )}
            <div ref={endRef} />
          </div>
        </div>

        {/* Suggestions after first answer + composer */}
        <div className="border-t border-slate-800 bg-slate-950 px-4 pb-4 pt-3">
          <div className="mx-auto w-full max-w-3xl">
            {messages.length > 0 && !loading && (
              <div className="mb-3 flex gap-2 overflow-x-auto pb-1">
                {SUGGESTIONS.slice(2).map((s) => (
                  <button key={s.label} onClick={() => void ask(s.prompt)} disabled={!!notReady} className="shrink-0 rounded-full border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-900 disabled:opacity-40">
                    {s.label}
                  </button>
                ))}
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void ask(input);
              }}
              className="flex items-end gap-2 rounded-2xl border border-slate-700 bg-slate-900 p-2 focus-within:border-sky-500"
            >
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    void ask(input);
                  }
                }}
                rows={1}
                maxLength={4000}
                placeholder={notReady ? 'AI provider not configured' : 'Ask about the evidence… (Enter to send, Shift+Enter for a new line)'}
                disabled={!!notReady}
                aria-label="Message the AI Analyst"
                className="max-h-40 min-h-[44px] flex-1 resize-none bg-transparent px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:cursor-not-allowed"
              />
              <button
                type="submit"
                disabled={loading || !input.trim() || !!notReady}
                className="rounded-xl bg-sky-500 p-2.5 text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                aria-label="Send message"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              </button>
            </form>
            <p className="mt-2 text-center text-[11px] text-slate-500">
              AI-generated analysis from limited, masked evidence for agent {RESTRICTED_AGENT.id} ({RESTRICTED_AGENT.name}). It cannot confirm incidents or take action; a human analyst must verify.
            </p>
          </div>
        </div>
      </section>

      {/* Local triage side panel (existing /api/ai-analyst endpoint) */}
      {showSide && (
        <aside className="hidden w-80 shrink-0 overflow-y-auto border-l border-slate-800 bg-slate-950 p-4 xl:block">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Local triage (rule-based)</h2>
          <p className="mt-1 text-xs text-slate-500">No AI model is used here. These counts come from the existing evidence endpoint.</p>
          {triage ? (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-2 text-center">
                {[['Alerts', triage.alertCount], ['High / critical', triage.highSeverityCount], ['Techniques', triage.techniqueCount], ['Triage score', `${triage.riskScore}/100`]].map(([k, v]) => (
                  <div key={String(k)} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                    <p className="text-lg font-semibold text-white">{v}</p>
                    <p className="text-[11px] text-slate-500">{k}</p>
                  </div>
                ))}
              </div>
              <p className="text-xs leading-5 text-slate-400">{triage.summary}</p>
              <ul className="space-y-2">
                {triage.findings.map((f, i) => (
                  <li key={i} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-medium text-slate-200">{f.title}</p>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p className="mt-1.5 text-xs leading-5 text-slate-500">{f.detail}</p>
                  </li>
                ))}
              </ul>
              <p className="text-[11px] text-slate-600">Updated {formatTime(triage.generatedAt)}</p>
            </div>
          ) : (
            <p className="mt-4 text-xs text-slate-500">Local triage data is unavailable.</p>
          )}
        </aside>
      )}

      {preview && <PreviewModal state={preview} onClose={() => setPreview(null)} />}
    </div>
  );
}

function StatusPill({ status, error }: { status: AiStatus | null; error: string }) {
  let text = 'Checking AI…';
  let cls = 'border-slate-700 text-slate-400';
  let dot = 'bg-slate-500';
  if (error) {
    text = 'AI status unavailable';
    cls = 'border-red-500/30 text-red-300';
    dot = 'bg-red-500';
  } else if (status) {
    if (!status.enabled) {
      text = 'AI disabled';
      cls = 'border-slate-700 text-slate-400';
    } else if (!status.configured) {
      text = 'Configuration required';
      cls = 'border-amber-500/30 text-amber-300';
      dot = 'bg-amber-400';
    } else {
      text = status.model.split('/').pop() ?? status.model;
      cls = 'border-emerald-500/30 text-emerald-300';
      dot = 'bg-emerald-400';
    }
  }
  return (
    <span className={clsx('hidden max-w-[14rem] items-center gap-1.5 truncate rounded-full border px-2.5 py-1 text-xs sm:inline-flex', cls)} title={status ? `${status.provider} · ${status.model}` : error}>
      <span className={clsx('h-1.5 w-1.5 shrink-0 rounded-full', dot)} />
      <span className="truncate">{text}</span>
    </span>
  );
}

function Avatar({ role }: { role: 'user' | 'assistant' }) {
  return (
    <div className={clsx('flex h-8 w-8 shrink-0 items-center justify-center rounded-full', role === 'user' ? 'bg-slate-700 text-slate-200' : 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30')}>
      {role === 'user' ? <User className="h-4 w-4" /> : <Sparkles className="h-4 w-4" />}
    </div>
  );
}

function EmptyChat({ onPick, disabled, context }: { onPick: (p: string) => void; disabled: boolean; context: string }) {
  return (
    <div className="flex flex-col items-center pt-10 text-center">
      <div className="rounded-2xl bg-sky-500/10 p-4 ring-1 ring-sky-500/30"><Sparkles className="h-8 w-8 text-sky-400" /></div>
      <h2 className="mt-5 text-2xl font-semibold text-white">How can I help with your investigation?</h2>
      <p className="mt-2 max-w-xl text-sm text-slate-400">
        I analyse correlated Wazuh evidence for <span className="text-slate-200">{context}</span>. I separate observed facts from hypotheses, never confirm incidents and never take action.
      </p>
      <div className="mt-8 grid w-full max-w-2xl gap-2 sm:grid-cols-2">
        {SUGGESTIONS.map((s) => (
          <button key={s.label} onClick={() => onPick(s.prompt)} disabled={disabled} className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3 text-left text-sm text-slate-200 transition hover:border-sky-500/40 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-50">
            {s.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard unavailable */
        }
      }}
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[11px] text-slate-500 hover:bg-slate-800 hover:text-slate-200"
    >
      {done ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />} {done ? 'Copied' : 'Copy'}
    </button>
  );
}

function MessageRow({ m, isLast, onRetry, disabled }: { m: ChatMessage; isLast: boolean; onRetry: () => void; disabled: boolean }) {
  if (m.error) {
    const hint =
      m.error.code === 'AI_NOT_CONFIGURED'
        ? 'Set OPENROUTER_API_KEY in backend/.env and restart the backend.'
        : m.error.code === 'AGENT_NOT_PERMITTED'
          ? `Live AI investigation is limited to agent ${RESTRICTED_AGENT.id} (${RESTRICTED_AGENT.name}).`
          : m.error.code === 'NO_EVIDENCE'
            ? 'No matching alerts were found, so nothing was sent to the AI.'
            : '';
    const retryable = !['AI_NOT_CONFIGURED', 'AI_DISABLED', 'AGENT_NOT_PERMITTED', 'NO_EVIDENCE', 'AI_AUTH_FAILED'].includes(m.error.code);
    return (
      <li className="flex gap-3">
        <Avatar role="assistant" />
        <div role="alert" className="min-w-0 flex-1 rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-sm text-red-200">
          <p className="font-semibold">{m.error.code === 'AI_RATE_LIMITED' || m.error.code === 'LOCAL_RATE_LIMITED' ? 'Rate limit reached' : 'The AI Analyst could not answer'}</p>
          <p className="mt-1 text-red-300/90">{m.error.message}</p>
          {m.error.retryAfterSeconds ? <p className="mt-1 text-xs text-red-300/70">Try again in about {m.error.retryAfterSeconds}s.</p> : null}
          {hint && <p className="mt-1 text-xs text-red-300/70">{hint}</p>}
          <p className="mt-2 font-mono text-[11px] text-red-300/50">{m.error.code}</p>
          {isLast && retryable && (
            <button onClick={onRetry} disabled={disabled} className="mt-3 rounded-md border border-red-400/40 px-3 py-1 text-xs hover:bg-red-500/10 disabled:opacity-50">Retry</button>
          )}
        </div>
      </li>
    );
  }
  if (m.role === 'user') {
    return (
      <li className="flex flex-row-reverse gap-3">
        <Avatar role="user" />
        <div className="max-w-[85%] whitespace-pre-wrap break-words rounded-2xl rounded-tr-sm bg-slate-800 px-4 py-2.5 text-[15px] leading-7 text-slate-100">{m.content}</div>
      </li>
    );
  }
  return (
    <li className="flex gap-3">
      <Avatar role="assistant" />
      <div className="min-w-0 flex-1">
        <Markdown text={m.content} />
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
          <CopyButton text={m.content} />
          {m.meta?.alertsIncluded != null && (
            <span>Based on {m.meta.alertsIncluded} of {m.meta.alertsConsidered} alerts{m.meta.masked ? ` · ${m.meta.masked} values masked` : ''}</span>
          )}
          {m.meta?.model && <span>{m.meta.model}</span>}
          <span>{formatTime(m.createdAt)}</span>
        </div>
      </div>
    </li>
  );
}

function PreviewModal({ state, onClose }: { state: { loading: boolean; data?: unknown; error?: string }; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Evidence preview">
      <button className="absolute inset-0 bg-black/70" onClick={onClose} aria-label="Close" />
      <div className="relative flex max-h-[85vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-slate-950 shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 p-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Evidence sent to the AI provider</h2>
            <p className="mt-1 text-xs text-slate-500">Masked and capped. IPs, users, hostnames and secrets are replaced with placeholders before leaving the backend.</p>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800" aria-label="Close"><X className="h-4 w-4" /></button>
        </div>
        <div className="overflow-auto p-4">
          {state.loading && <p className="text-sm text-slate-400">Collecting evidence…</p>}
          {state.error && <p className="text-sm text-red-300">{state.error}</p>}
          {!!state.data && <pre className="whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">{JSON.stringify(state.data, null, 2)}</pre>}
        </div>
      </div>
    </div>
  );
}
