import test from 'node:test';
import assert from 'node:assert/strict';
import { loadAiConfig } from '../ai/config';

test('live AI investigation scope is immutable: Wazuh agent 001 (win-11)', () => {
  const cfg = loadAiConfig({
    LIVE_INVESTIGATION_AGENT_ID: '000',
    LIVE_INVESTIGATION_AGENT_NAME: 'SPLUNK',
  } as NodeJS.ProcessEnv);

  assert.equal(cfg.restrictedAgentId, '001');
  assert.equal(cfg.restrictedAgentName, 'win-11');
});
