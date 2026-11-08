import test from 'node:test';
import assert from 'node:assert/strict';
import { buildEvidence, EvidenceError } from '../ai/evidence';
import { Masker } from '../ai/Masker';
import { cfg, hit, StubSource } from './helpers';

const now = new Date('2026-10-30T07:00:00.000Z');

test('recent: only agent 001 evidence is requested and returned', async () => {
  const src = new StubSource([
    hit('a1', { ts: '2026-10-30T06:00:00Z' }),
    hit('a2', { ts: '2026-10-30T06:01:00Z', level: 12 }),
    hit('x1', { agentId: '002', agentName: 'kali', ts: '2026-10-30T06:02:00Z', level: 14 }),
  ]);
  const ev = await buildEvidence(src, { type: 'recent' }, cfg(), new Masker(), now);
  assert.equal(src.calls[0][1].agentId, '001');
  assert.deepEqual(ev.timeline.map((a) => a.id), ['a1', 'a2']);
  assert.equal(ev.stats.alertsConsidered, 2);
  assert.equal(ev.scope.agentName, 'win-11');
});

test('alert / investigation for another agent is rejected with AGENT_NOT_PERMITTED (403)', async () => {
  const src = new StubSource([hit('x1', { agentId: '002', agentName: 'kali' }), hit('a1')]);
  await assert.rejects(buildEvidence(src, { type: 'alert', alertId: 'x1' }, cfg(), undefined, now), (e: any) => e instanceof EvidenceError && e.code === 'AGENT_NOT_PERMITTED' && e.httpStatus === 403);
  await assert.rejects(buildEvidence(src, { type: 'investigation', alertIds: ['a1', 'x1'] }, cfg(), undefined, now), (e: any) => e.code === 'AGENT_NOT_PERMITTED');
});

test('no evidence -> NO_EVIDENCE 422; unknown ids -> 404; bad context -> 400', async () => {
  await assert.rejects(buildEvidence(new StubSource([]), { type: 'recent' }, cfg(), undefined, now), (e: any) => e.code === 'NO_EVIDENCE' && e.httpStatus === 422);
  await assert.rejects(buildEvidence(new StubSource([]), { type: 'alert', alertId: 'nope' }, cfg(), undefined, now), (e: any) => e.httpStatus === 404);
  await assert.rejects(buildEvidence(new StubSource([]), { type: 'investigation', alertIds: [] }, cfg(), undefined, now), (e: any) => e.code === 'BAD_CONTEXT');
  await assert.rejects(buildEvidence(new StubSource([]), { type: 'bogus' } as any, cfg(), undefined, now), (e: any) => e.code === 'BAD_CONTEXT');
});

test('caps evidence, collapses floods, keeps highest severity, never sends all raw alerts', async () => {
  const docs = [] as any[];
  for (let i = 0; i < 300; i++) docs.push(hit(`f${i}`, { ts: new Date(Date.parse('2026-10-30T05:00:00Z') + i * 1000).toISOString(), level: 5 }));
  docs.push(hit('crit', { ts: '2026-10-30T05:01:00Z', level: 13, desc: 'Critical thing', ruleId: '99999' }));
  const ev = await buildEvidence(new StubSource(docs), { type: 'recent' }, cfg({ AI_MAX_EVIDENCE_ALERTS: '20' }), undefined, now);
  assert.equal(ev.stats.alertsConsidered, 301);
  assert.ok(ev.timeline.length <= 20);
  assert.ok(ev.timeline.some((a) => a.id === 'crit'));
  assert.equal(ev.timeline.filter((a) => a.ruleId === '60122').length, 5); // max 5 samples of an identical flood
  assert.equal(ev.stats.truncated, true);
  assert.equal(ev.ruleGroups.find((g) => g.ruleId === '60122')?.count, 300);
});

test('alert context includes the focus alert and neighbours within the window', async () => {
  const src = new StubSource([
    hit('n1', { ts: '2026-10-30T06:00:00Z' }),
    hit('f', { ts: '2026-10-30T06:05:00Z', level: 10 }),
    hit('far', { ts: '2026-10-30T03:00:00Z' }),
  ]);
  const ev = await buildEvidence(src, { type: 'alert', alertId: 'f' }, cfg(), undefined, now);
  assert.equal(ev.focus?.id, 'f');
  assert.deepEqual(ev.timeline.map((a) => a.id).sort(), ['f', 'n1']);
});

test('masking the evidence removes IPs, users, hostnames and secrets', async () => {
  const masker = new Masker();
  const ev = await buildEvidence(new StubSource([hit('a1')]), { type: 'recent' }, cfg(), masker, now);
  const text = JSON.stringify(masker.maskDeep(ev));
  for (const secret of ['203.0.113.9', 'alice', 'hunter2', '192.168.252.20']) assert.ok(!text.includes(secret), `${secret} leaked: ${text}`);
  assert.ok(text.includes('T1110') && text.includes('60122')); // analytic metadata survives
});
