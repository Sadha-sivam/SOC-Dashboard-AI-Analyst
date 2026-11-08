/** Hand-off of an investigation context from other pages to the AI Analyst page. */
export type AiContext =
  | { type: 'recent'; label?: string }
  | { type: 'alert'; alertId: string; label?: string }
  | { type: 'investigation'; alertIds: string[]; label?: string };

const KEY = 'soc.ai.pendingContext';

/** Live AI investigation is restricted by the backend to this agent; the UI mirrors it for clearer affordances. */
export const RESTRICTED_AGENT = { id: '001', name: 'win-11' };

export function setPendingAiContext(ctx: AiContext): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(ctx));
  } catch {
    /* storage unavailable */
  }
}

export function takePendingAiContext(): AiContext | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    if (!raw) return null;
    sessionStorage.removeItem(KEY);
    return JSON.parse(raw) as AiContext;
  } catch {
    return null;
  }
}
