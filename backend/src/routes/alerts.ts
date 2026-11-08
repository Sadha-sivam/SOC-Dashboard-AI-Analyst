import { Router } from 'express';
import { severityFromLevel } from '../services/severity';

/** Additive alert endpoints. The existing GET /api/alerts in index.ts is unchanged. */
export function createAlertsRouter(wazuh: {
  fetchAlertSummary(hours: number): Promise<any>;
  fetchAlertsByIds(ids: string[]): Promise<any[]>;
}): Router {
  const router = Router();

  // Accurate aggregate counts + trend (not limited to the 1000-hit page the list endpoint returns).
  router.get('/summary', async (req, res) => {
    const hours = Math.min(168, Math.max(1, Number.parseInt(String(req.query.hours ?? '24'), 10) || 24));
    try {
      const { data, interval } = await wazuh.fetchAlertSummary(hours);
      const sev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const b of data.aggregations?.severity?.buckets ?? []) sev[b.key] = b.doc_count;
      res.json({
        source: 'Wazuh Indexer',
        windowHours: hours,
        interval,
        total: typeof data.hits?.total === 'object' ? data.hits.total.value : Number(data.hits?.total ?? 0),
        totalIsLowerBound: data.hits?.total?.relation === 'gte',
        severity: sev,
        trend: (data.aggregations?.trend?.buckets ?? []).map((b: any) => ({
          time: b.key_as_string ?? new Date(b.key).toISOString(),
          total: b.doc_count,
          critical: b.critical?.doc_count ?? 0,
          high: b.high?.doc_count ?? 0,
        })),
        agents: (data.aggregations?.agents?.buckets ?? []).map((b: any) => ({
          id: b.key,
          name: b.name?.buckets?.[0]?.key ?? 'Unknown',
          count: b.doc_count,
        })),
        topRules: (data.aggregations?.rules?.buckets ?? []).map((b: any) => {
          const src = b.sample?.hits?.hits?.[0]?._source?.rule ?? {};
          return { ruleId: b.key, count: b.doc_count, description: src.description ?? 'No description', level: Number(src.level ?? 0) };
        }),
      });
    } catch (e: any) {
      console.error('Failed to build alert summary:', e.message);
      res.status(502).json({ error: 'Failed to build alert summary from Wazuh Indexer' });
    }
  });

  // Full alert document for the detail view.
  router.get('/:id', async (req, res) => {
    try {
      const hits = await wazuh.fetchAlertsByIds([req.params.id]);
      if (!hits.length) return res.status(404).json({ error: 'Alert not found' });
      const raw = hits[0]._source ?? {};
      const level = Number(raw?.rule?.level ?? 0);
      res.json({
        id: hits[0]._id,
        severity: severityFromLevel(level),
        level,
        timestamp: raw['@timestamp'] ?? null,
        rule: raw.rule ?? {},
        agent: raw.agent ?? {},
        data: raw.data ?? {},
        fullLog: raw.full_log ?? null,
        raw,
      });
    } catch (e: any) {
      console.error('Failed to fetch alert detail:', e.message);
      res.status(502).json({ error: 'Failed to fetch alert from Wazuh Indexer' });
    }
  });

  return router;
}
