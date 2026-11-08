import { AiConfig } from './config';

export type AiErrorCode =
  | 'AI_DISABLED'
  | 'AI_NOT_CONFIGURED'
  | 'AI_AUTH_FAILED'
  | 'AI_INSUFFICIENT_CREDITS'
  | 'AI_MODEL_UNAVAILABLE'
  | 'AI_RATE_LIMITED'
  | 'AI_TIMEOUT'
  | 'AI_NETWORK_ERROR'
  | 'AI_PROVIDER_ERROR'
  | 'AI_BAD_RESPONSE';

export class AiError extends Error {
  constructor(
    public code: AiErrorCode,
    message: string,
    public httpStatus: number,
    public retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ChatResult {
  content: string;
  model: string;
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number };
  triedModels: string[];
}

/** Provider-agnostic chat interface (the existing AIProvider interface is incident-shaped and left untouched). */
export interface ChatProvider {
  readonly name: string;
  isConfigured(): boolean;
  chat(messages: ChatMessage[]): Promise<ChatResult>;
}

function parseRetryAfter(res: Response): number | undefined {
  const ra = res.headers.get('retry-after');
  if (ra) {
    const n = Number(ra);
    if (Number.isFinite(n)) return Math.max(1, Math.ceil(n));
    const d = Date.parse(ra);
    if (Number.isFinite(d)) return Math.max(1, Math.ceil((d - Date.now()) / 1000));
  }
  const reset = res.headers.get('x-ratelimit-reset'); // OpenRouter: epoch millis
  if (reset) {
    const n = Number(reset);
    if (Number.isFinite(n)) {
      const ms = n > 1e12 ? n - Date.now() : n * 1000 - Date.now();
      return Math.max(1, Math.ceil(ms / 1000));
    }
  }
  return undefined;
}

function errorMessageFromBody(body: any): string {
  const m = body?.error?.message ?? body?.message;
  return typeof m === 'string' ? m.slice(0, 300) : '';
}

export class OpenRouterProvider implements ChatProvider {
  readonly name = 'openrouter';

  constructor(
    private getConfig: () => AiConfig,
    private fetchImpl: typeof fetch = fetch,
  ) {}

  isConfigured(): boolean {
    const c = this.getConfig();
    return c.enabled && !!c.apiKey;
  }

  async chat(messages: ChatMessage[]): Promise<ChatResult> {
    const cfg = this.getConfig();
    if (!cfg.enabled) throw new AiError('AI_DISABLED', 'The AI Analyst is disabled (AI_ENABLED=false).', 503);
    if (!cfg.apiKey) {
      throw new AiError(
        'AI_NOT_CONFIGURED',
        'AI provider is not configured. Set OPENROUTER_API_KEY in backend/.env and restart the backend.',
        503,
      );
    }

    const models = [cfg.model, ...cfg.fallbackModels.filter((m) => m !== cfg.model)];
    const tried: string[] = [];
    let lastError: AiError | undefined;

    for (const model of models) {
      tried.push(model);
      try {
        const result = await this.callOnce(cfg, model, messages);
        return { ...result, triedModels: tried };
      } catch (e) {
        if (!(e instanceof AiError)) throw e;
        lastError = e;
        // Only fall through to the next model when it could help; auth/credit problems affect every model.
        const retryable = e.code === 'AI_MODEL_UNAVAILABLE' || e.code === 'AI_RATE_LIMITED' || e.code === 'AI_PROVIDER_ERROR';
        if (!retryable) break;
      }
    }
    throw lastError ?? new AiError('AI_PROVIDER_ERROR', 'AI request failed.', 502);
  }

  private async callOnce(cfg: AiConfig, model: string, messages: ChatMessage[]): Promise<Omit<ChatResult, 'triedModels'>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);

    let res: Response;
    try {
      res = await this.fetchImpl(`${cfg.baseUrl}/chat/completions`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${cfg.apiKey}`,
          'Content-Type': 'application/json',
          ...(cfg.siteUrl ? { 'HTTP-Referer': cfg.siteUrl } : {}),
          'X-Title': cfg.siteTitle,
        },
        body: JSON.stringify({
          model,
          messages,
          max_tokens: cfg.maxTokens,
          temperature: cfg.temperature,
          stream: false,
        }),
      });
    } catch (e: any) {
      clearTimeout(timer);
      if (e?.name === 'AbortError') {
        throw new AiError('AI_TIMEOUT', `The AI provider did not respond within ${Math.round(cfg.timeoutMs / 1000)}s.`, 504);
      }
      throw new AiError('AI_NETWORK_ERROR', 'Could not reach the AI provider (network error).', 502);
    }

    try {
      let body: any = null;
      const text = await res.text();
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = null;
      }

      if (!res.ok) throw this.mapHttpError(res, body, model);

      // OpenRouter can return HTTP 200 with an error object (e.g. upstream failure mid-request).
      if (body?.error) {
        const code = Number(body.error.code);
        throw this.mapHttpError({ status: Number.isFinite(code) ? code : 502, headers: res.headers } as Response, body, model);
      }

      const content = body?.choices?.[0]?.message?.content;
      if (typeof content !== 'string' || !content.trim()) {
        throw new AiError('AI_BAD_RESPONSE', 'The AI provider returned an empty or malformed response.', 502);
      }
      const u = body.usage;
      return {
        content,
        model: typeof body.model === 'string' ? body.model : model,
        usage: u
          ? { promptTokens: u.prompt_tokens, completionTokens: u.completion_tokens, totalTokens: u.total_tokens }
          : undefined,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private mapHttpError(res: Response, body: any, model: string): AiError {
    const detail = errorMessageFromBody(body);
    switch (res.status) {
      case 401:
      case 403:
        return new AiError('AI_AUTH_FAILED', 'The AI provider rejected the API key. Check OPENROUTER_API_KEY.', 502);
      case 402:
        return new AiError('AI_INSUFFICIENT_CREDITS', 'The AI provider reports insufficient credits or quota for this model.', 502);
      case 404:
        return new AiError('AI_MODEL_UNAVAILABLE', `Model "${model}" is unavailable. Set OPENROUTER_MODEL to another model.`, 502);
      case 408:
        return new AiError('AI_TIMEOUT', 'The AI provider timed out.', 504);
      case 429: {
        const wait = parseRetryAfter(res);
        return new AiError(
          'AI_RATE_LIMITED',
          `The AI provider rate limit was reached for "${model}".${wait ? ` Retry in about ${wait}s.` : ''}`,
          429,
          wait,
        );
      }
      case 400:
        if (/no endpoints found|not a valid model|model.*(not found|unavailable)/i.test(detail)) {
          return new AiError('AI_MODEL_UNAVAILABLE', `Model "${model}" is unavailable. Set OPENROUTER_MODEL to another model.`, 502);
        }
        return new AiError('AI_PROVIDER_ERROR', `The AI provider rejected the request${detail ? `: ${detail}` : '.'}`, 502);
      default:
        return new AiError('AI_PROVIDER_ERROR', `The AI provider returned an error (HTTP ${res.status}).`, 502);
    }
  }
}

/** Simple in-memory sliding-window limiter to protect free-tier quotas. */
export class RateLimiter {
  private hits: number[] = [];
  constructor(private limitFn: () => number, private windowMs = 60_000) {}

  /** Returns 0 if allowed (and records the hit), otherwise seconds to wait. */
  take(now = Date.now()): number {
    this.hits = this.hits.filter((t) => now - t < this.windowMs);
    if (this.hits.length >= this.limitFn()) {
      return Math.max(1, Math.ceil((this.hits[0] + this.windowMs - now) / 1000));
    }
    this.hits.push(now);
    return 0;
  }
}
