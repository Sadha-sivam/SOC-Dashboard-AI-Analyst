export const API_URL: string = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';

export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, { signal });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const msg = (body as { error?: string | { message?: string } } | null)?.error;
    throw new Error(typeof msg === 'string' ? msg : msg?.message || `Request failed (HTTP ${res.status})`);
  }
  return body as T;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return 'Unknown';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return '';
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
