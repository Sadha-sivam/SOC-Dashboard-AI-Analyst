import { Router, Request, Response } from 'express';
import { loadAiConfig, AiConfig } from '../ai/config';
import { buildEvidence, AlertSource, EvidenceContext, EvidenceError } from '../ai/evidence';
import { Masker } from '../ai/Masker';
import { SYSTEM_PROMPT, evidenceMessage } from '../ai/prompt';
import { AiError, ChatMessage, ChatProvider, OpenRouterProvider, RateLimiter } from '../ai/OpenRouterProvider';

export interface AiRouterDeps {
  wazuh: AlertSource;
  provider?: ChatProvider;
  getConfig?: () => AiConfig;
}

function sendError(res: Response, code: string, message: string, status: number, extra: Record<string, unknown> = {}) {
  return res.status(status).json({ error: { code, message, ...extra } });
}

function parseContext(raw: any): EvidenceContext {
  const t = raw?.type ?? 'recent';
  if (t === 'recent') return { type: 'recent' };
  if (t === 'alert') return { type: 'alert', alertId: String(raw?.alertId ?? '') };
  if (t === 'investigation') {
    return { type: 'investigation', alertIds: Array.isArray(raw?.alertIds) ? raw.alertIds.map(String) : [] };
  }
  throw new EvidenceError('BAD_CONTEXT', 'Unknown context type.', 400);
}

export function createAiRouter(deps: AiRouterDeps): Router {
  const router = Router();
  const getConfig = deps.getConfig ?? (() => loadAiConfig());
  const provider = deps.provider ?? new OpenRouterProvider(getConfig);
  const limiter = new RateLimiter(() => getConfig().rateLimitPerMinute);

  // Prepare masked evidence + conversation for a request body. Shared by /preview and /chat.
  async function prepare(body: any, cfg: AiConfig) {
    const context = parseContext(body?.context);
    const masker = new Masker();
    const evidence = await buildEvidence(deps.wazuh, context, cfg, masker);
    const maskedEvidence = masker.maskDeep(evidence);
    return { context, masker, evidence, maskedEvidence };
  }

  function parseMessages(body: any, cfg: AiConfig): ChatMessage[] {
    const input = Array.isArray(body?.messages) ? body.messages : [];
    // The client may only supply user/assistant turns; any "system" role is discarded.
    const cleaned: ChatMessage[] = input
      .filter((m: any) => (m?.role === 'user' || m?.role === 'assistant') && typeof m?.content === 'string')
      .map((m: any) => ({ role: m.role, content: String(m.content).slice(0, 4000) }));
    return cleaned.slice(-cfg.maxHistoryMessages);
  }

  router.get('/status', (_req: Request, res: Response) => {
    const cfg = getConfig();
    res.json({
      enabled: cfg.enabled,
      provider: cfg.provider,
      configured: provider.isConfigured(),
      model: cfg.model,
      fallbackModels: cfg.fallbackModels,
      restrictedAgent: { id: cfg.restrictedAgentId, name: cfg.restrictedAgentName },
      limits: {
        rateLimitPerMinute: cfg.rateLimitPerMinute,
        maxEvidenceAlerts: cfg.maxEvidenceAlerts,
        evidenceWindowHours: cfg.evidenceWindowHours,
      },
      // Never includes the API key.
      message: !cfg.enabled
        ? 'AI Analyst is disabled.'
        : provider.isConfigured()
          ? 'AI provider configured.'
          : 'Configuration required: set OPENROUTER_API_KEY in backend/.env.',
    });
  });

  // Shows exactly what would be sent to the provider (masked), without calling it.
  router.post('/preview', async (req: Request, res: Response) => {
    const cfg = getConfig();
    try {
      const { maskedEvidence, masker } = await prepare(req.body, cfg);
      res.json({ evidence: maskedEvidence, masking: masker.summary() });
    } catch (e) {
      return handleEvidenceError(res, e);
    }
  });

  router.post('/chat', async (req: Request, res: Response) => {
    const cfg = getConfig();

    if (!cfg.enabled) return sendError(res, 'AI_DISABLED', 'The AI Analyst is disabled (AI_ENABLED=false).', 503);
    if (!provider.isConfigured()) {
      return sendError(
        res,
        'AI_NOT_CONFIGURED',
        'AI provider is not configured. Set OPENROUTER_API_KEY in backend/.env and restart the backend.',
        503,
      );
    }

    const history = parseMessages(req.body, cfg);
    if (!history.length || history[history.length - 1].role !== 'user') {
      return sendError(res, 'BAD_REQUEST', 'messages must end with a user message.', 400);
    }

    const wait = limiter.take();
    if (wait > 0) {
      res.setHeader('Retry-After', String(wait));
      return sendError(res, 'LOCAL_RATE_LIMITED', `Too many AI requests. Try again in ${wait}s.`, 429, {
        retryAfterSeconds: wait,
      });
    }

    let prepared;
    try {
      prepared = await prepare(req.body, cfg);
    } catch (e) {
      return handleEvidenceError(res, e);
    }
    const { masker, maskedEvidence } = prepared;

    const messages: ChatMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: evidenceMessage(maskedEvidence) },
      { role: 'assistant', content: 'Understood. I will use only this evidence and keep facts and hypotheses separate.' },
      ...history.map((m) => ({ role: m.role, content: masker.mask(m.content) })),
    ];

    try {
      const result = await provider.chat(messages);
      return res.json({
        reply: masker.unmask(result.content),
        model: result.model,
        usage: result.usage,
        evidence: {
          agentId: cfg.restrictedAgentId,
          agentName: cfg.restrictedAgentName,
          contextType: prepared.context.type,
          windowHours: cfg.evidenceWindowHours,
          ...prepared.evidence.stats,
          masking: masker.summary(),
        },
        generatedAt: new Date().toISOString(),
        disclaimer: 'AI-generated analysis from limited evidence. A human analyst must verify before any conclusion or action.',
      });
    } catch (e) {
      if (e instanceof AiError) {
        if (e.retryAfterSeconds) res.setHeader('Retry-After', String(e.retryAfterSeconds));
        console.error(`[AI] ${e.code}: ${e.message}`);
        return sendError(res, e.code, e.message, e.httpStatus, e.retryAfterSeconds ? { retryAfterSeconds: e.retryAfterSeconds } : {});
      }
      console.error('[AI] Unexpected error:', e instanceof Error ? e.stack : String(e));
      return sendError(res, 'AI_INTERNAL_ERROR', 'Unexpected error while contacting the AI provider.', 500);
    }
  });

  function handleEvidenceError(res: Response, e: unknown) {
    if (e instanceof EvidenceError) return sendError(res, e.code, e.message, e.httpStatus);
    console.error('[AI] Evidence collection failed:', (e as Error)?.message);
    return sendError(res, 'EVIDENCE_UNAVAILABLE', 'Could not collect evidence from the Wazuh Indexer.', 502);
  }

  return router;
}
