import type { AiContext } from './aiContext';

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
  /** Present on assistant messages produced by the backend. */
  meta?: {
    model?: string;
    alertsConsidered?: number;
    alertsIncluded?: number;
    masked?: number;
    totalTokens?: number;
  };
  /** Present when the request failed; error messages are never sent back to the model. */
  error?: { code: string; message: string; retryAfterSeconds?: number };
};

export type Conversation = {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  context: AiContext;
  messages: ChatMessage[];
};

const KEY = 'soc.ai.conversations.v1';
const MAX_CONVERSATIONS = 30;

export const uid = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`);

export function loadConversations(): Conversation[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as Conversation[]) : [];
  } catch {
    return [];
  }
}

export function saveConversations(list: Conversation[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list.slice(0, MAX_CONVERSATIONS)));
  } catch {
    /* storage full/unavailable: conversations stay in memory for this session */
  }
}

export function newConversation(context: AiContext = { type: 'recent' }): Conversation {
  const now = new Date().toISOString();
  return { id: uid(), title: 'New conversation', createdAt: now, updatedAt: now, context, messages: [] };
}
