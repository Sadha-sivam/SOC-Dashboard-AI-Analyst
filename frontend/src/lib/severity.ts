export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Same bands the backend API routes use (12+ critical, 10-11 high, 7-9 medium, 4-6 low). */
export function severityFromLevel(level: number): Severity {
  if (level >= 12) return 'CRITICAL';
  if (level >= 10) return 'HIGH';
  if (level >= 7) return 'MEDIUM';
  if (level >= 4) return 'LOW';
  return 'INFO';
}

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export const SEVERITY_STYLE: Record<Severity, { badge: string; dot: string; hex: string; label: string }> = {
  CRITICAL: { badge: 'border-red-500/40 bg-red-500/10 text-red-300', dot: 'bg-red-500', hex: '#ef4444', label: 'Critical' },
  HIGH: { badge: 'border-orange-500/40 bg-orange-500/10 text-orange-300', dot: 'bg-orange-500', hex: '#f97316', label: 'High' },
  MEDIUM: { badge: 'border-amber-400/40 bg-amber-400/10 text-amber-200', dot: 'bg-amber-400', hex: '#fbbf24', label: 'Medium' },
  LOW: { badge: 'border-sky-400/40 bg-sky-400/10 text-sky-300', dot: 'bg-sky-400', hex: '#38bdf8', label: 'Low' },
  INFO: { badge: 'border-slate-600 bg-slate-700/30 text-slate-300', dot: 'bg-slate-500', hex: '#64748b', label: 'Info' },
};

export function asSeverity(value: string | undefined | null): Severity {
  const v = String(value ?? '').toUpperCase();
  return (SEVERITY_ORDER as string[]).includes(v) ? (v as Severity) : 'INFO';
}
