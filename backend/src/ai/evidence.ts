import { SEVERITY_RANK, severityFromLevel, Severity } from '../services/severity';
import { Masker } from './Masker';
import { AiConfig } from './config';

/** Minimal surface of WazuhService that evidence collection needs (easy to stub in tests). */
export interface AlertSource {
  fetchAlerts(opts: {
    since: Date;
    until?: Date;
    size?: number;
    order?: 'asc' | 'desc';
    agentId?: string;
    minLevel?: number;
  }): Promise<any[]>;
  fetchAlertsByIds(ids: string[]): Promise<any[]>;
}

export type EvidenceContext =
  | { type: 'recent' }
  | { type: 'alert'; alertId: string }
  | { type: 'investigation'; alertIds: string[] };

export class EvidenceError extends Error {
  constructor(
    public code: 'AGENT_NOT_PERMITTED' | 'NO_EVIDENCE' | 'BAD_CONTEXT',
    message: string,
    public httpStatus: number,
  ) {
    super(message);
  }
}

export interface EvidenceAlert {
  id: string;
  time: string | null;
  level: number;
  severity: Severity;
  ruleId: string;
  description: string;
  groups?: string[];
  mitre?: { ids: string[]; tactics: string[]; techniques: string[] };
  srcIp?: string;
  dstIp?: string;
  user?: string;
  details?: Record<string, string>;
  logExcerpt?: string;
}

export interface EvidencePackage {
  scope: {
    agentId: string;
    agentName: string;
    contextType: string;
    windowHours: number;
    generatedAt: string;
  };
  stats: {
    alertsConsidered: number;
    alertsIncluded: number;
    ruleGroups: number;
    correlationGroups: number;
    truncated: boolean;
    severityCounts: Record<string, number>;
  };
  correlationGroups: Array<{
    id: string;
    firstSeen: string;
    lastSeen: string;
    eventCount: number;
    highestSeverity: Severity;
    note: string;
  }>;
  ruleGroups: Array<{
    ruleId: string;
    description: string;
    level: number;
    count: number;
    firstSeen: string | null;
    lastSeen: string | null;
    mitreIds: string[];
  }>;
  /** Chronological, capped sample of the most relevant alerts. */
  timeline: EvidenceAlert[];
  focus?: EvidenceAlert;
}

const CORRELATION_WINDOW_MS = 5 * 60 * 1000; // same window as the existing correlation logic

function pick(obj: any, path: string): unknown {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function s(v: unknown, max = 200): string | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  const str = String(v);
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function arr(v: unknown): string[] {
  if (v === undefined || v === null) return [];
  return (Array.isArray(v) ? v : [v]).map((x) => String(x));
}

/** Reduce a raw Wazuh document to the fields an analyst (or model) actually needs. */
export function compactAlert(hit: any, masker?: Masker): EvidenceAlert {
  const raw = hit._source ?? {};
  const level = Number(raw?.rule?.level ?? 0);
  const win = raw?.data?.win?.eventdata ?? {};
  const sys = raw?.data?.win?.system ?? {};

  const user = s(
    win.targetUserName ?? win.subjectUserName ?? raw?.data?.dstuser ?? raw?.data?.srcuser ?? raw?.data?.user,
  );
  for (const u of [win.targetUserName, win.subjectUserName, raw?.data?.dstuser, raw?.data?.srcuser, raw?.data?.user]) {
    masker?.registerUser(u);
  }
  masker?.registerHost(raw?.agent?.name);
  masker?.registerHost(sys.computer);
  masker?.registerHost(win.workstationName);

  const details: Record<string, string> = {};
  const put = (k: string, v: unknown, max = 200) => {
    const val = s(v, max);
    if (val) details[k] = val;
  };
  put('eventId', sys.eventID);
  put('channel', sys.channel);
  put('logonType', win.logonType);
  put('status', win.status ?? win.subStatus);
  put('process', win.processName ?? win.image ?? win.newProcessName);
  put('parentProcess', win.parentImage ?? win.parentProcessName);
  put('commandLine', win.commandLine, 300);
  put('workstation', win.workstationName);
  put('syscheckPath', raw?.syscheck?.path);
  put('syscheckEvent', raw?.syscheck?.event);
  put('decoder', raw?.decoder?.name);
  put('location', raw?.location);

  const out: EvidenceAlert = {
    id: String(hit._id ?? ''),
    time: raw['@timestamp'] ?? null,
    level,
    severity: severityFromLevel(level),
    ruleId: String(raw?.rule?.id ?? 'unknown'),
    description: String(raw?.rule?.description ?? 'No description'),
  };
  const groups = arr(raw?.rule?.groups);
  if (groups.length) out.groups = groups.slice(0, 8);
  const mitreIds = arr(raw?.rule?.mitre?.id);
  if (mitreIds.length) {
    out.mitre = {
      ids: mitreIds,
      tactics: arr(raw?.rule?.mitre?.tactic),
      techniques: arr(raw?.rule?.mitre?.technique),
    };
  }
  const src = s(raw?.data?.srcip ?? raw?.data?.src_ip ?? win.ipAddress ?? raw?.data?.win?.eventdata?.sourceIp);
  if (src && src !== '-') out.srcIp = src;
  const dst = s(raw?.data?.dstip ?? raw?.data?.destip ?? win.destinationIp);
  if (dst) out.dstIp = dst;
  if (user) out.user = user;
  if (Object.keys(details).length) out.details = details;
  const log = s(raw?.full_log, 300);
  if (log) out.logExcerpt = log;
  return out;
}

function assertPermitted(hits: any[], cfg: AiConfig) {
  for (const hit of hits) {
    const id = String(hit?._source?.agent?.id ?? '');
    if (id !== cfg.restrictedAgentId) {
      throw new EvidenceError(
        'AGENT_NOT_PERMITTED',
        `Live AI investigation is restricted to agent ${cfg.restrictedAgentId} (${cfg.restrictedAgentName}). ` +
          `The requested alert belongs to a different agent.`,
        403,
      );
    }
  }
}

export async function buildEvidence(
  source: AlertSource,
  context: EvidenceContext,
  cfg: AiConfig,
  masker?: Masker,
  now: Date = new Date(),
): Promise<EvidencePackage> {
  const windowStart = new Date(now.getTime() - cfg.evidenceWindowHours * 3600 * 1000);
  let hits: any[] = [];
  let focusId: string | undefined;

  if (context.type === 'recent') {
    hits = await source.fetchAlerts({ since: windowStart, size: 500, order: 'desc', agentId: cfg.restrictedAgentId });
  } else if (context.type === 'alert') {
    if (!context.alertId || typeof context.alertId !== 'string') {
      throw new EvidenceError('BAD_CONTEXT', 'alertId is required.', 400);
    }
    const found = await source.fetchAlertsByIds([context.alertId]);
    if (!found.length) throw new EvidenceError('NO_EVIDENCE', 'The requested alert was not found.', 404);
    assertPermitted(found, cfg);
    focusId = String(found[0]._id);
    const t = new Date(found[0]._source['@timestamp']).getTime();
    const around = await source.fetchAlerts({
      since: new Date(t - 15 * 60 * 1000),
      until: new Date(t + 15 * 60 * 1000),
      size: 200,
      order: 'asc',
      agentId: cfg.restrictedAgentId,
    });
    const map = new Map<string, any>(around.map((h) => [String(h._id), h]));
    map.set(focusId, found[0]);
    hits = [...map.values()];
  } else if (context.type === 'investigation') {
    const ids = Array.isArray(context.alertIds) ? context.alertIds.filter((x) => typeof x === 'string') : [];
    if (!ids.length) throw new EvidenceError('BAD_CONTEXT', 'alertIds must be a non-empty array.', 400);
    if (ids.length > 200) throw new EvidenceError('BAD_CONTEXT', 'Too many alertIds (max 200).', 400);
    hits = await source.fetchAlertsByIds(ids);
    if (!hits.length) throw new EvidenceError('NO_EVIDENCE', 'None of the requested alerts were found.', 404);
    assertPermitted(hits, cfg);
  } else {
    throw new EvidenceError('BAD_CONTEXT', 'Unknown context type.', 400);
  }

  // Defence in depth: even for 'recent' make sure nothing from another agent slipped in.
  hits = hits.filter((h) => String(h?._source?.agent?.id ?? '') === cfg.restrictedAgentId);
  if (!hits.length) {
    throw new EvidenceError(
      'NO_EVIDENCE',
      `No alerts were found for agent ${cfg.restrictedAgentId} (${cfg.restrictedAgentName}) in the selected scope.`,
      422,
    );
  }

  // Chronological order.
  hits.sort(
    (a, b) => new Date(a._source['@timestamp']).getTime() - new Date(b._source['@timestamp']).getTime(),
  );

  // Pre-register identifiers so masking is consistent regardless of which alert mentions them first.
  const compact = hits.map((h) => compactAlert(h, masker));
  const timeOf = (a: EvidenceAlert) => new Date(a.time ?? 0).getTime();

  // Correlation groups: same endpoint, 5-minute gap (matches the existing story logic).
  const correlationGroups: EvidencePackage['correlationGroups'] = [];
  for (const a of compact) {
    const last = correlationGroups[correlationGroups.length - 1];
    if (last && timeOf(a) - new Date(last.lastSeen).getTime() <= CORRELATION_WINDOW_MS) {
      last.lastSeen = a.time ?? last.lastSeen;
      last.eventCount++;
      if (SEVERITY_RANK[a.severity] > SEVERITY_RANK[last.highestSeverity]) last.highestSeverity = a.severity;
    } else {
      correlationGroups.push({
        id: `G${correlationGroups.length + 1}`,
        firstSeen: a.time ?? '',
        lastSeen: a.time ?? '',
        eventCount: 1,
        highestSeverity: a.severity,
        note: '',
      });
    }
  }
  for (const g of correlationGroups) {
    g.note =
      g.eventCount > 1
        ? 'Grouped by endpoint and five-minute gaps only; grouping alone does not prove the events are related.'
        : 'Single event.';
  }

  // Rule groups (collapse repeated identical detections).
  const ruleMap = new Map<string, EvidencePackage['ruleGroups'][number]>();
  for (const a of compact) {
    const key = `${a.ruleId}|${a.description}`;
    const g = ruleMap.get(key);
    if (g) {
      g.count++;
      g.lastSeen = a.time;
      for (const m of a.mitre?.ids ?? []) if (!g.mitreIds.includes(m)) g.mitreIds.push(m);
    } else {
      ruleMap.set(key, {
        ruleId: a.ruleId,
        description: a.description,
        level: a.level,
        count: 1,
        firstSeen: a.time,
        lastSeen: a.time,
        mitreIds: [...(a.mitre?.ids ?? [])],
      });
    }
  }
  const ruleGroups = [...ruleMap.values()].sort((a, b) => b.level - a.level || b.count - a.count).slice(0, 25);

  // Select the most relevant alerts under the cap: focus alert, then by severity and recency, de-duplicated by rule+description
  // (keep at most 5 samples per identical detection so a flood does not crowd out other evidence).
  const cap = cfg.maxEvidenceAlerts;
  const perRule = new Map<string, number>();
  const ranked = [...compact].sort(
    (a, b) =>
      (b.id === focusId ? 1 : 0) - (a.id === focusId ? 1 : 0) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      timeOf(b) - timeOf(a),
  );
  const chosen: EvidenceAlert[] = [];
  for (const a of ranked) {
    if (chosen.length >= cap) break;
    const key = `${a.ruleId}|${a.description}`;
    const n = perRule.get(key) ?? 0;
    if (n >= 5 && a.id !== focusId) continue;
    perRule.set(key, n + 1);
    chosen.push(a);
  }
  chosen.sort((a, b) => timeOf(a) - timeOf(b));

  const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const a of compact) severityCounts[a.severity]++;

  return {
    scope: {
      agentId: cfg.restrictedAgentId,
      agentName: cfg.restrictedAgentName,
      contextType: context.type,
      windowHours: cfg.evidenceWindowHours,
      generatedAt: now.toISOString(),
    },
    stats: {
      alertsConsidered: compact.length,
      alertsIncluded: chosen.length,
      ruleGroups: ruleMap.size,
      correlationGroups: correlationGroups.length,
      truncated: chosen.length < compact.length,
      severityCounts,
    },
    correlationGroups: correlationGroups.slice(-15),
    ruleGroups,
    timeline: chosen,
    ...(focusId ? { focus: compact.find((a) => a.id === focusId) } : {}),
  };
}
