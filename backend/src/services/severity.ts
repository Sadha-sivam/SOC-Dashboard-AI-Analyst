export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Same bands the existing /api/alerts, /api/mitre and /api/ai-analyst routes use. */
export function severityFromLevel(level: number): Severity {
  if (level >= 12) return 'CRITICAL';
  if (level >= 10) return 'HIGH';
  if (level >= 7) return 'MEDIUM';
  if (level >= 4) return 'LOW';
  return 'INFO';
}

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};
