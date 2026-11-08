import { loadAiConfig } from '../ai/config';

export function cfg(overrides: Record<string, string> = {}) {
  return loadAiConfig({ OPENROUTER_API_KEY: 'test-key-NOT-REAL', ...overrides } as NodeJS.ProcessEnv);
}

export function hit(id: string, o: Partial<{ agentId: string; agentName: string; level: number; desc: string; ts: string; srcip: string; user: string; ruleId: string; fullLog: string }> = {}) {
  return {
    _id: id,
    _source: {
      '@timestamp': o.ts ?? new Date(Date.now() - 60_000).toISOString(),
      agent: { id: o.agentId ?? '001', name: o.agentName ?? 'win-11', ip: '192.168.252.20' },
      rule: { id: o.ruleId ?? '60122', level: o.level ?? 5, description: o.desc ?? 'Logon failure - Unknown user or bad password', mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
      data: { srcip: o.srcip ?? '203.0.113.9', win: { eventdata: { targetUserName: o.user ?? 'alice', logonType: '3' }, system: { eventID: '4625', computer: 'win-11' } } },
      full_log: o.fullLog ?? 'Logon failure for alice from 203.0.113.9 password=hunter2',
    },
  };
}

export class StubSource {
  calls: any[] = [];
  constructor(public docs: any[]) {}
  async fetchAlerts(opts: any) {
    this.calls.push(['fetchAlerts', opts]);
    let r = this.docs.filter((d) => !opts.agentId || d._source.agent.id === opts.agentId);
    r = r.filter((d) => new Date(d._source['@timestamp']) > opts.since && (!opts.until || new Date(d._source['@timestamp']) <= opts.until));
    return r;
  }
  async fetchAlertsByIds(ids: string[]) {
    this.calls.push(['fetchAlertsByIds', ids]);
    return this.docs.filter((d) => ids.includes(d._id));
  }
}
