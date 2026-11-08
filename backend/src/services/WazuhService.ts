import axios from 'axios';
import https from 'https';
import dotenv from 'dotenv';
dotenv.config();

export class WazuhService {
  private baseUrl: string;
  private token: string | null = null;
  private httpsAgent: https.Agent;

  constructor() {
    const host = process.env.WAZUH_HOST || '192.168.252.9';
    const port = process.env.WAZUH_PORT || '55000';
    this.baseUrl = `https://${host}:${port}`;
    this.httpsAgent = new https.Agent({ rejectUnauthorized: false });
  }

  async authenticate(): Promise<string> {
    const username = process.env.WAZUH_USERNAME;
    const password = process.env.WAZUH_PASSWORD;
    if (!username || !password) throw new Error('WAZUH_USERNAME or WAZUH_PASSWORD missing');
    const authHeader = Buffer.from(`${username}:${password}`).toString('base64');
    try {
      const response = await axios.get(`${this.baseUrl}/security/user/authenticate`, {
        headers: { Authorization: `Basic ${authHeader}` },
        httpsAgent: this.httpsAgent
      });
      this.token = response.data.data.token;
      return this.token as string;
    } catch (error: any) {
      throw new Error(`Failed to authenticate with Wazuh API: ${error.message}`);
    }
  }

  private async getAuthToken(): Promise<string> {
    if (!this.token) await this.authenticate();
    return this.token as string;
  }

  async getManagerInfo(): Promise<any> {
    try {
      const token = await this.getAuthToken();
      const response = await axios.get(`${this.baseUrl}/manager/info`, {
        headers: { Authorization: `Bearer ${token}` },
        httpsAgent: this.httpsAgent
      });
      return response.data.data;
    } catch (error: any) {
      if (error.response?.status === 401) {
        this.token = null;
        return this.getManagerInfo();
      }
      throw error;
    }
  }

  async getAgents(): Promise<any> {
    try {
      const token = await this.getAuthToken();
      const response = await axios.get(`${this.baseUrl}/agents`, {
        headers: { Authorization: `Bearer ${token}` },
        httpsAgent: this.httpsAgent
      });
      return response.data.data.affected_items;
    } catch (error: any) {
      if (error.response?.status === 401) {
        this.token = null;
        return this.getAgents();
      }
      throw error;
    }
  }

  async fetchRecentAlerts(since: Date): Promise<any[]> {
    const host = process.env.WAZUH_HOST || '192.168.252.9';
    const indexerUsername = process.env.INDEXER_USERNAME;
    const indexerPassword = process.env.INDEXER_PASSWORD;

    if (!indexerUsername || !indexerPassword) throw new Error('INDEXER creds missing');

    const indexerUrl = `https://${host}:9200/wazuh-alerts-*/_search`;
    const authHeader = Buffer.from(`${indexerUsername}:${indexerPassword}`).toString('base64');

    const query = {
      query: { range: { "@timestamp": { gt: since.toISOString() } } },
      sort: [ { "@timestamp": { order: "asc" } } ],
      size: 1000
    };

    const response = await axios.post(indexerUrl, query, {
      headers: { Authorization: `Basic ${authHeader}` },
      httpsAgent: this.httpsAgent,
      timeout: 10000
    });

    return response.data.hits.hits;
  }

  // ---------------------------------------------------------------------------
  // Additive helpers (the methods above are unchanged).
  // ---------------------------------------------------------------------------

  private async indexerSearch(body: unknown): Promise<any> {
    const host = process.env.WAZUH_HOST || '192.168.252.9';
    const indexerUsername = process.env.INDEXER_USERNAME;
    const indexerPassword = process.env.INDEXER_PASSWORD;
    if (!indexerUsername || !indexerPassword) throw new Error('INDEXER creds missing');

    const authHeader = Buffer.from(`${indexerUsername}:${indexerPassword}`).toString('base64');
    const response = await axios.post(`https://${host}:9200/wazuh-alerts-*/_search`, body, {
      headers: { Authorization: `Basic ${authHeader}` },
      httpsAgent: this.httpsAgent,
      timeout: 10000,
    });
    return response.data;
  }

  /**
   * Alert search with explicit ordering and optional agent restriction.
   * Unlike fetchRecentAlerts (ascending, so a >size window returns the OLDEST
   * alerts), this defaults to newest-first.
   */
  async fetchAlerts(opts: {
    since: Date;
    until?: Date;
    size?: number;
    order?: 'asc' | 'desc';
    agentId?: string;
    minLevel?: number;
  }): Promise<any[]> {
    const filter: any[] = [
      {
        range: {
          '@timestamp': {
            gt: opts.since.toISOString(),
            ...(opts.until ? { lte: opts.until.toISOString() } : {}),
          },
        },
      },
    ];
    if (opts.agentId) filter.push({ term: { 'agent.id': opts.agentId } });
    if (opts.minLevel) filter.push({ range: { 'rule.level': { gte: opts.minLevel } } });

    const data = await this.indexerSearch({
      query: { bool: { filter } },
      sort: [{ '@timestamp': { order: opts.order ?? 'desc' } }],
      size: Math.min(opts.size ?? 500, 1000),
    });
    return data.hits.hits;
  }

  /** Fetch specific alert documents by Indexer _id. */
  async fetchAlertsByIds(ids: string[]): Promise<any[]> {
    if (!ids.length) return [];
    const data = await this.indexerSearch({
      query: { ids: { values: ids } },
      size: Math.min(ids.length, 200),
    });
    return data.hits.hits;
  }

  /**
   * Accurate counts via aggregations (not limited by the 1000-hit page size).
   * Severity bands match the existing API routes: 12+ critical, 10-11 high,
   * 7-9 medium, 4-6 low, below 4 info.
   */
  async fetchAlertSummary(hours: number): Promise<any> {
    const since = new Date(Date.now() - hours * 3600 * 1000);
    const interval = hours <= 6 ? '10m' : hours <= 48 ? '1h' : '6h';
    return this.indexerSearch({
      size: 0,
      track_total_hits: true,
      query: { range: { '@timestamp': { gt: since.toISOString() } } },
      aggs: {
        severity: {
          range: {
            field: 'rule.level',
            ranges: [
              { key: 'info', to: 4 },
              { key: 'low', from: 4, to: 7 },
              { key: 'medium', from: 7, to: 10 },
              { key: 'high', from: 10, to: 12 },
              { key: 'critical', from: 12 },
            ],
          },
        },
        trend: {
          date_histogram: { field: '@timestamp', fixed_interval: interval, min_doc_count: 0 },
          aggs: {
            critical: { filter: { range: { 'rule.level': { gte: 12 } } } },
            high: { filter: { range: { 'rule.level': { gte: 10, lt: 12 } } } },
          },
        },
        agents: { terms: { field: 'agent.id', size: 10 }, aggs: { name: { terms: { field: 'agent.name', size: 1 } } } },
        rules: {
          terms: { field: 'rule.id', size: 8 },
          aggs: { sample: { top_hits: { size: 1, _source: ['rule.description', 'rule.level'] } } },
        },
      },
    }).then((data) => ({ data, interval, since }));
  }
}
