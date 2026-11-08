/** AI configuration. Live investigation scope is deliberately immutable. */

export interface AiConfig {
  enabled: boolean;
  provider: 'openrouter';
  apiKey: string | undefined;
  baseUrl: string;
  model: string;
  fallbackModels: string[];
  timeoutMs: number;
  maxTokens: number;
  temperature: number;
  maxEvidenceAlerts: number;
  maxHistoryMessages: number;
  rateLimitPerMinute: number;
  evidenceWindowHours: number;
  siteUrl: string | undefined;
  siteTitle: string;
  restrictedAgentId: string;
  restrictedAgentName: string;
}

export function loadAiConfig(env: NodeJS.ProcessEnv = process.env): AiConfig {
  const num = (name: string, fb: number, min: number, max: number) => {
    const n = Number.parseInt(env[name] ?? '', 10);
    return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fb;
  };
  const temp = Number.parseFloat(env.AI_TEMPERATURE ?? '');
  return {
    enabled: (env.AI_ENABLED ?? 'true').toLowerCase() !== 'false',
    provider: 'openrouter',
    apiKey: env.OPENROUTER_API_KEY?.trim() || undefined,
    baseUrl: (env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1').replace(/\/+$/, ''),
    // Free model availability changes often. Override OPENROUTER_MODEL if this one is unavailable.
    model: env.OPENROUTER_MODEL?.trim() || 'meta-llama/llama-3.3-70b-instruct:free',
    fallbackModels: (env.OPENROUTER_FALLBACK_MODELS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    timeoutMs: num('AI_TIMEOUT_MS', 60_000, 1_000, 300_000),
    maxTokens: num('AI_MAX_TOKENS', 1800, 100, 8000),
    temperature: Number.isFinite(temp) ? Math.min(1, Math.max(0, temp)) : 0.2,
    maxEvidenceAlerts: num('AI_MAX_EVIDENCE_ALERTS', 40, 5, 150),
    maxHistoryMessages: num('AI_MAX_HISTORY_MESSAGES', 12, 2, 40),
    rateLimitPerMinute: num('AI_RATE_LIMIT_PER_MINUTE', 10, 1, 120),
    evidenceWindowHours: num('AI_EVIDENCE_WINDOW_HOURS', 24, 1, 168),
    siteUrl: env.OPENROUTER_SITE_URL?.trim() || undefined,
    siteTitle: env.OPENROUTER_SITE_TITLE?.trim() || 'SOC Investigator',
    // Security boundary: never allow environment configuration to redirect live AI
    // investigations to another endpoint. Wazuh agent 001 is the only permitted scope.
    restrictedAgentId: '001',
    restrictedAgentName: 'win-11',
  };
}
