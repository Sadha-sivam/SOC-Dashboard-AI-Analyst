import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import dotenv from 'dotenv';
import { NormalizationService } from './services/NormalizationService';
import { CorrelationEngine } from './services/CorrelationEngine';
import { WazuhService } from './services/WazuhService';
import { createAiRouter } from './routes/ai';
import { createAlertsRouter } from './routes/alerts';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const normalizer = new NormalizationService();
const correlator = new CorrelationEngine();
const wazuh = new WazuhService();

const incidentsDb = new Map();

let isPolling = false;
let pollCount = 0;
let lastPollTime = new Date();
const processedAlertIds = new Set<string>();

async function pollWazuhAlerts() {
  if (isPolling) return;
  isPolling = true;
  pollCount++;

  try {
    // 30 seconds overlap window to handle Indexer delays
    const queryTime = new Date(lastPollTime.getTime() - 30 * 1000);
    const hits = await wazuh.fetchRecentAlerts(queryTime);

    let newAlertsCount = 0;
    let skippedCount = 0;

    for (const hit of hits) {
      const alertId = hit._id;
      const rawAlert = hit._source;

      if (processedAlertIds.has(alertId)) {
        skippedCount++;
        continue;
      }
      processedAlertIds.add(alertId);
      newAlertsCount++;

      if (processedAlertIds.size > 10000) {
        const iterator = processedAlertIds.values();
        processedAlertIds.delete(iterator.next().value as string);
      }

      const normalized = normalizer.normalize(rawAlert);
      const incident = correlator.processAlert(normalized);

      if (incident) {
        if (!incident.id) incident.id = `INC-${Math.floor(Math.random() * 10000)}`;
        incidentsDb.set(incident.id, incident);

        console.log(`\n[Poll #${pollCount}] ⚡ NEW LIVE ALERT DETECTED!`);
        console.log(`   -> Indexer _id: ${alertId}`);
        console.log(`   -> Alert Timestamp: ${rawAlert['@timestamp']}`);
        console.log(`   -> Description: ${rawAlert.rule?.description}`);
        console.log(`   -> Normalizer processed: YES`);
        console.log(`   -> CorrelationEngine processed: YES`);
        console.log(`   -> Socket.IO Emitting 'incident_update' for INCIDENT: ${incident.id}`);
        io.emit('incident_update', incident);
      }

      const alertTime = new Date(rawAlert['@timestamp']);
      if (alertTime > lastPollTime) {
        lastPollTime = alertTime;
      }
    }

    console.log(`[Poll #${pollCount}] Hits: ${hits.length} | Processed (New): ${newAlertsCount} | Skipped (Dupe): ${skippedCount} | Watermark: ${lastPollTime.toISOString()}`);

  } catch (error: any) {
    console.error(`[Poll #${pollCount}] Failed:`, error.message);
  } finally {
    isPolling = false;
  }
}

// API ENDPOINTS
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/agents', async (_req, res) => {
  try {
    const agents = await wazuh.getAgents();

    const endpoints = agents.map((agent: any) => ({
      id: agent.id ?? 'N/A',
      name: agent.name ?? 'Unknown',
      ip: agent.ip ?? 'N/A',
      status: agent.status ?? 'unknown',
      operatingSystem: agent.os?.name ?? 'Unknown',
      osVersion: agent.os?.version ?? '',
      lastKeepAlive: agent.lastKeepAlive ?? null,
      nodeName: agent.node_name ?? 'N/A',
    }));

    res.json({
      source: 'Wazuh API',
      count: endpoints.length,
      summary: {
        active: endpoints.filter((agent: any) => agent.status === 'active').length,
        disconnected: endpoints.filter((agent: any) => agent.status === 'disconnected').length,
        other: endpoints.filter(
          (agent: any) => !['active', 'disconnected'].includes(agent.status)
        ).length,
      },
      endpoints,
    });
  } catch (error: any) {
    console.error('Failed to fetch Wazuh agents:', error.message);
    res.status(502).json({
      error: 'Failed to fetch endpoints from Wazuh API',
    });
  }
});
app.get('/api/incidents', (req, res) => res.json(Array.from(incidentsDb.values())));

app.get('/api/stories', async (_req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hits = await wazuh.fetchRecentAlerts(since);

    const normalizedAlerts = hits
      .map((hit: any) => ({
        id: hit._id,
        alert: normalizer.normalize(hit._source),
      }))
      .sort(
        (a: any, b: any) =>
          a.alert.timestamp.getTime() - b.alert.timestamp.getTime()
      );

    const stories: any[] = [];
    const activeStories = new Map<string, any>();
    const windowMs = 5 * 60 * 1000;

    for (const item of normalizedAlerts) {
      const alert = item.alert;
      const target = alert.targetIp || alert.agentName;

      if (!target || target === 'unknown') continue;

      let story = activeStories.get(target);

      if (
        !story ||
        alert.timestamp.getTime() -
          new Date(story.lastSeen).getTime() > windowMs
      ) {
        story = {
          id: `STORY-${stories.length + 1}`,
          title: `Suspicious Activity on ${target}`,
          target,
          source: alert.sourceIp || 'Unknown',
          severity: alert.severity,
          eventCount: 0,
          firstSeen: alert.timestamp.toISOString(),
          lastSeen: alert.timestamp.toISOString(),
          riskScore: 0,
          mitreTechniques: [],
          events: [],
          explanation: '',
        };

        stories.push(story);
        activeStories.set(target, story);
      }

      story.events.push({
        id: item.id,
        timestamp: alert.timestamp.toISOString(),
        severity: alert.severity,
        ruleId: alert.ruleId,
        description: alert.description,
        sourceIp: alert.sourceIp || 'Unknown',
        targetIp: alert.targetIp || target,
        agentName: alert.agentName,
        mitreTechniques: alert.mitreTechnique || [],
      });

      story.eventCount++;
      story.lastSeen = alert.timestamp.toISOString();

      const severityRisk: Record<string, number> = {
        LOW: 10,
        MEDIUM: 20,
        HIGH: 40,
        CRITICAL: 60,
      };

      story.riskScore = Math.min(
        100,
        story.riskScore + (severityRisk[alert.severity] || 10)
      );

      if (
        (severityRisk[alert.severity] || 0) >
        (severityRisk[story.severity] || 0)
      ) {
        story.severity = alert.severity;
      }

      for (const technique of alert.mitreTechnique || []) {
        if (!story.mitreTechniques.includes(technique)) {
          story.mitreTechniques.push(technique);
        }
      }
    }

    for (const story of stories) {
      story.explanation =
        story.eventCount > 1
          ? `${story.eventCount} events affected the same endpoint within five-minute correlation windows. Review the event sequence to determine whether the activity is related.`
          : 'A single event was observed. More evidence is needed to determine whether it is suspicious.';

      story.riskScore = Math.min(100, story.riskScore);
    }

    stories.sort(
      (a, b) =>
        new Date(b.lastSeen).getTime() -
        new Date(a.lastSeen).getTime()
    );

    res.json({
      source: 'Wazuh Indexer',
      windowHours: 24,
      count: stories.length,
      stories,
    });
  } catch (error: any) {
    console.error('Failed to build attack stories:', error.message);
    res.status(502).json({
      error: 'Failed to build attack stories from Wazuh alerts',
    });
  }
});

app.get('/api/stories/:id', async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hits = await wazuh.fetchRecentAlerts(since);

    const normalizedAlerts = hits
      .map((hit: any) => ({
        id: hit._id,
        alert: normalizer.normalize({
          ...hit._source,
          id: hit._id,
        }),
      }))
      .filter((item: any) => !Number.isNaN(item.alert.timestamp.getTime()))
      .sort(
        (a: any, b: any) =>
          a.alert.timestamp.getTime() - b.alert.timestamp.getTime()
      );

    const stories: any[] = [];
    const activeStories = new Map<string, any>();
    const windowMs = 5 * 60 * 1000;

    for (const item of normalizedAlerts) {
      const alert = item.alert;
      const target = alert.targetIp || alert.agentName;
      if (!target || target === 'unknown') continue;

      let story = activeStories.get(target);

      if (
        !story ||
        alert.timestamp.getTime() -
          new Date(story.lastSeen).getTime() > windowMs
      ) {
        story = {
          id: `STORY-${stories.length + 1}`,
          title: `Observed activity on ${target}`,
          target,
          source: alert.sourceIp || 'Unknown',
          severity: alert.severity,
          eventCount: 0,
          firstSeen: alert.timestamp.toISOString(),
          lastSeen: alert.timestamp.toISOString(),
          events: [],
        };

        stories.push(story);
        activeStories.set(target, story);
      }

      story.events.push({
        id: item.id,
        timestamp: alert.timestamp.toISOString(),
        severity: alert.severity,
        ruleId: alert.ruleId,
        description: alert.description,
        sourceIp: alert.sourceIp || 'Unknown',
        targetIp: alert.targetIp || target,
        agentName: alert.agentName,
        agentId: alert.agentId,
        mitreTechniques: alert.mitreTechnique || [],
        ruleLevel: Number(alert.rawEvent?.rule?.level ?? 0),
        rawEvent: alert.rawEvent,
      });

      story.eventCount++;
      story.lastSeen = alert.timestamp.toISOString();

      const priority: Record<string, number> = {
        LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4,
      };
      if ((priority[alert.severity] || 0) > (priority[story.severity] || 0)) {
        story.severity = alert.severity;
      }
    }

    const selected = stories.find((story) => story.id === req.params.id);

    if (!selected) {
      return res.status(404).json({
        error: 'Story not found in the last 24 hours. It may have expired from the investigation window.',
      });
    }

    res.json({
      source: 'Wazuh Indexer',
      windowHours: 24,
      generatedAt: new Date().toISOString(),
      reviewStatus: 'PENDING_ANALYST_REVIEW',
      correlationNote: selected.eventCount > 1
        ? 'These events were grouped by endpoint and a five-minute time window. This grouping alone does not prove that they are part of one attack.'
        : 'One event was observed. Additional evidence is needed to determine its significance.',
      story: selected,
    });
  } catch (error: any) {
    console.error('Failed to fetch story evidence:', error.message);
    res.status(502).json({ error: 'Failed to fetch story evidence from Wazuh Indexer' });
  }
});

app.get('/api/mitre', async (_req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hits = await wazuh.fetchRecentAlerts(since);

    const techniques = new Map<string, any>();

    for (const hit of hits) {
      const raw = hit._source;
      const mitre = raw?.rule?.mitre;

      if (!mitre) continue;

      const ids = Array.isArray(mitre.id)
        ? mitre.id
        : mitre.id
          ? [mitre.id]
          : [];

      const names = Array.isArray(mitre.technique)
        ? mitre.technique
        : mitre.technique
          ? [mitre.technique]
          : [];

      const tactics = Array.isArray(mitre.tactic)
        ? mitre.tactic
        : mitre.tactic
          ? [mitre.tactic]
          : [];

      ids.forEach((value: unknown, index: number) => {
        const techniqueId = String(value);
        if (!techniqueId) return;

        const name = names[index] || names[0] || 'Technique name unavailable';
        const tactic = tactics[0] || 'Tactic not specified';
        const key = techniqueId;

        if (!techniques.has(key)) {
          techniques.set(key, {
            id: techniqueId,
            name: String(name),
            tactics: [],
            eventCount: 0,
            severityCounts: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0,
            },
            latestSeen: null,
            alerts: [],
          });
        }

        const item = techniques.get(key);

        if (
          item.name === 'Technique name unavailable' &&
          name !== 'Technique name unavailable'
        ) {
          item.name = String(name);
        }

        if (!item.tactics.includes(String(tactic))) {
          item.tactics.push(String(tactic));
        }

        const level = Number(raw?.rule?.level ?? 0);
        const severity =
          level >= 12 ? 'critical' :
          level >= 10 ? 'high' :
          level >= 7 ? 'medium' :
          level >= 4 ? 'low' : 'info';

        item.eventCount++;
        item.severityCounts[severity]++;

        const timestamp = raw?.['@timestamp'] ?? null;

        if (
          timestamp &&
          (!item.latestSeen ||
            new Date(timestamp).getTime() >
              new Date(item.latestSeen).getTime())
        ) {
          item.latestSeen = timestamp;
        }

        item.alerts.push({
          id: hit._id,
          timestamp,
          ruleId: raw?.rule?.id ?? 'N/A',
          level,
          severity,
          description: raw?.rule?.description ?? 'No description',
          agentName: raw?.agent?.name ?? 'Unknown',
        });
      });
    }

    const results = Array.from(techniques.values())
      .map((item) => ({
        ...item,
        alerts: item.alerts.sort(
          (a: any, b: any) =>
            new Date(b.timestamp || 0).getTime() -
            new Date(a.timestamp || 0).getTime()
        ),
      }))
      .sort((a, b) => b.eventCount - a.eventCount);

    res.json({
      source: 'Wazuh Indexer',
      windowHours: 24,
      alertCount: hits.length,
      mappedEventCount: results.reduce(
        (total, item) => total + item.eventCount,
        0
      ),
      techniqueCount: results.length,
      techniques: results,
    });
  } catch (error: any) {
    console.error('Failed to build MITRE data:', error.message);
    res.status(502).json({
      error: 'Failed to build MITRE ATT&CK data from Wazuh',
    });
  }
});


app.get('/api/ai-analyst', async (_req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hits = await wazuh.fetchRecentAlerts(since);

    const alerts = hits.map((hit: any) => {
      const raw = hit._source ?? {};
      const level = Number(raw?.rule?.level ?? 0);
      const severity = level >= 12 ? 'CRITICAL' : level >= 10 ? 'HIGH' : level >= 7 ? 'MEDIUM' : level >= 4 ? 'LOW' : 'INFO';
      const mitre = raw?.rule?.mitre ?? {};
      const ids = Array.isArray(mitre.id) ? mitre.id : mitre.id ? [mitre.id] : [];
      return {
        id: String(hit._id ?? `${raw?.['@timestamp'] ?? 'alert'}-${raw?.rule?.id ?? 'unknown'}`),
        timestamp: raw?.['@timestamp'] ?? null,
        ruleId: String(raw?.rule?.id ?? 'N/A'),
        level, severity,
        description: String(raw?.rule?.description ?? 'No description'),
        agentName: String(raw?.agent?.name ?? 'Unknown'),
        agentIp: String(raw?.agent?.ip ?? 'N/A'),
        sourceIp: String(raw?.data?.srcip ?? raw?.data?.src_ip ?? raw?.srcip ?? 'N/A'),
        mitreTechniques: ids.map((id: unknown) => String(id)),
      };
    });

    const criticalCount = alerts.filter((a: any) => a.severity === 'CRITICAL').length;
    const highCount = alerts.filter((a: any) => a.severity === 'HIGH').length;
    const mediumCount = alerts.filter((a: any) => a.severity === 'MEDIUM').length;
    const failedAuthenticationCount = alerts.filter((a: any) =>
      /failed (password|login|logon|auth)|authentication failure|invalid user|invalid password|login failure/i.test(a.description)
    ).length;
    const successfulAuthenticationCount = alerts.filter((a: any) =>
      /accepted password|successful (login|logon|authentication)|login successful|authentication succeeded/i.test(a.description)
    ).length;
    const techniques = Array.from(new Set(alerts.flatMap((a: any) => a.mitreTechniques))).sort();
    const riskScore = Math.min(100, criticalCount * 20 + highCount * 10 + mediumCount * 2);

    const findings: Array<{ title: string; detail: string; severity: string }> = [];
    if (criticalCount) findings.push({
      title: 'Critical-severity detections present',
      detail: `${criticalCount} alert(s) have Wazuh rule level 12 or higher. Review each rule, raw event, and affected host to confirm impact.`,
      severity: 'CRITICAL',
    });
    if (highCount) findings.push({
      title: 'High-severity detections present',
      detail: `${highCount} alert(s) have Wazuh rule levels 10–11. Validate these and look for related events on the same endpoint and source.`,
      severity: 'HIGH',
    });
    if (failedAuthenticationCount) findings.push({
      title: 'Authentication failures observed',
      detail: `${failedAuthenticationCount} alert description(s) match common authentication-failure wording. This does not prove brute force; correlate account, source IP, and time.`,
      severity: failedAuthenticationCount >= 10 ? 'HIGH' : 'MEDIUM',
    });
    if (successfulAuthenticationCount) findings.push({
      title: 'Successful authentication wording observed',
      detail: `${successfulAuthenticationCount} alert description(s) match successful-authentication wording. Check whether any success followed failures for the same account and source.`,
      severity: 'MEDIUM',
    });
    if (techniques.length) findings.push({
      title: 'MITRE technique metadata available',
      detail: `${techniques.length} distinct technique ID(s) appear in Wazuh alert metadata. A mapping does not prove a technique succeeded.`,
      severity: 'INFO',
    });
    if (!findings.length) findings.push({
      title: 'No high-priority pattern detected by current rules',
      detail: 'Current triage rules did not identify critical/high detections or common authentication patterns. This does not prove the environment is safe.',
      severity: 'INFO',
    });

    const recommendations = [
      'Review the full Wazuh event, rule ID, timestamp, and raw fields for the highest-severity alerts.',
      'Group events by endpoint, source IP, user/account, and time window before deciding whether they form one incident.',
      'For authentication activity, compare failures and successes for the same account and source; verify whether the activity was expected.',
      'Review process execution, network connections, and relevant Windows/Linux security logs around the alert time.',
      'Validate MITRE mappings and document supporting and contradicting evidence. Obtain analyst approval before response actions.',
    ];
    if (criticalCount || highCount) recommendations.unshift(
      'Prioritise critical/high alerts. If compromise is corroborated, follow your incident-response process and obtain approval before isolating a system.'
    );

    const priority: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    const prioritisedAlerts = [...alerts].sort((a: any, b: any) =>
      priority[b.severity] - priority[a.severity] ||
      new Date(b.timestamp ?? 0).getTime() - new Date(a.timestamp ?? 0).getTime()
    ).slice(0, 100);

    res.json({
      source: 'Wazuh Indexer',
      analysisType: 'Local evidence-based triage (no external LLM)',
      windowHours: 24,
      generatedAt: new Date().toISOString(),
      alertCount: alerts.length,
      highSeverityCount: criticalCount + highCount,
      criticalCount,
      riskScore,
      failedAuthenticationCount,
      successfulAuthenticationCount,
      techniqueCount: techniques.length,
      techniques,
      summary: `Reviewed ${alerts.length} Wazuh alert(s) from the last 24 hours. ${criticalCount} were critical, ${highCount} high, and ${mediumCount} medium by Wazuh rule level. ${failedAuthenticationCount} alert description(s) matched common authentication-failure wording and ${successfulAuthenticationCount} matched successful-authentication wording. These are triage signals only; correlate and verify before declaring an incident.`,
      findings,
      recommendations,
      alerts: prioritisedAlerts,
    });
  } catch (error: any) {
    console.error('Failed to build AI Analyst evidence:', error.message);
    res.status(502).json({ error: 'Failed to analyse recent Wazuh alerts' });
  }
});

app.get('/api/alerts', async (_req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const hits = await wazuh.fetchRecentAlerts(since);

    const alerts = hits.map((hit: any) => ({
      id: hit._id,
      timestamp: hit._source?.['@timestamp'] ?? null,
      ruleId: hit._source?.rule?.id ?? 'N/A',
      level: Number(hit._source?.rule?.level ?? 0),
      description: hit._source?.rule?.description ?? 'No description',
      agentName: hit._source?.agent?.name ?? 'Unknown',
      agentId: hit._source?.agent?.id ?? 'N/A',
      agentIp: hit._source?.agent?.ip ?? 'N/A',
    }));

    res.json({
      source: 'Wazuh Indexer',
      windowHours: 24,
      count: alerts.length,
      alerts,
    });
  } catch (error: any) {
    console.error('Failed to fetch alerts:', error.message);
    res.status(502).json({
      error: 'Failed to fetch alerts from Wazuh Indexer',
    });
  }
});

// Additive routes (existing routes above are unchanged)
app.use('/api/alerts', createAlertsRouter(wazuh));
app.use('/api/ai', createAiRouter({ wazuh }));

app.post('/api/webhook/wazuh', (req, res) => res.status(200).json({ status: 'deprecated' }));

io.on('connection', (socket) => {
  socket.emit('initial_data', Array.from(incidentsDb.values()));
});

const PORT = process.env.PORT || 3000;

async function bootstrap() {
  console.log('Establishing baseline from Indexer to avoid clock drift...');
  try {
    // Fetch the absolute newest alert in the database to establish the baseline
    const hits = await wazuh.fetchRecentAlerts(new Date(0));
    if (hits.length > 0) {
      const newest = hits[hits.length - 1]; // fetchRecentAlerts sorts asc, so last is newest
      lastPollTime = new Date(newest._source['@timestamp']);
    } else {
      lastPollTime = new Date();
    }
    console.log(`Baseline established. High-water mark set to: ${lastPollTime.toISOString()}`);

    server.listen(PORT, () => {
      console.log(`🚀 SOC Backend is running on port ${PORT}`);
      console.log(`📡 Polling Engine starting for strictly LIVE ingestion...`);
      setInterval(pollWazuhAlerts, 5000);
    });
  } catch (err) {
    console.error('Bootstrap failed:', err);
  }
}

bootstrap();
