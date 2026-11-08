import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { AiError, OpenRouterProvider, RateLimiter } from '../ai/OpenRouterProvider';
import { cfg } from './helpers';

const msgs = [{ role: 'user' as const, content: 'hi' }];

function fakeFetch(handler: (url: string, init: any) => Response | Promise<Response>): typeof fetch {
  return ((url: any, init: any) => Promise.resolve(handler(String(url), init))) as any;
}
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

async function expectAi(p: Promise<unknown>, code: string) {
  await assert.rejects(p, (e: any) => e instanceof AiError && e.code === code, `expected ${code}`);
}

test('success: sends key + model only to configured base URL, parses reply and usage', async () => {
  let seen: any;
  const p = new OpenRouterProvider(() => cfg({ OPENROUTER_MODEL: 'm/one:free' }), fakeFetch((url, init) => {
    seen = { url, init };
    return json(200, { model: 'm/one:free', choices: [{ message: { content: 'hello' } }], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } });
  }));
  const r = await p.chat(msgs);
  assert.equal(r.content, 'hello');
  assert.equal(r.usage?.totalTokens, 5);
  assert.equal(seen.url, 'https://openrouter.ai/api/v1/chat/completions');
  assert.equal(seen.init.headers.Authorization, 'Bearer test-key-NOT-REAL');
  assert.equal(JSON.parse(seen.init.body).model, 'm/one:free');
});

test('not configured: no network call and clear error', async () => {
  let called = false;
  const p = new OpenRouterProvider(() => cfg({ OPENROUTER_API_KEY: '' }), fakeFetch(() => { called = true; return json(200, {}); }));
  assert.equal(p.isConfigured(), false);
  await expectAi(p.chat(msgs), 'AI_NOT_CONFIGURED');
  assert.equal(called, false);
});

test('disabled', async () => {
  const p = new OpenRouterProvider(() => cfg({ AI_ENABLED: 'false' }), fakeFetch(() => json(200, {})));
  await expectAi(p.chat(msgs), 'AI_DISABLED');
});

test('401 -> AI_AUTH_FAILED (no fallback attempt, no key in message)', async () => {
  let n = 0;
  const p = new OpenRouterProvider(() => cfg({ OPENROUTER_FALLBACK_MODELS: 'b' }), fakeFetch(() => { n++; return json(401, { error: { message: 'bad key' } }); }));
  await assert.rejects(p.chat(msgs), (e: any) => e.code === 'AI_AUTH_FAILED' && !e.message.includes('test-key'));
  assert.equal(n, 1);
});

test('402 -> insufficient credits', async () => {
  const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(402, { error: { message: 'x' } })));
  await expectAi(p.chat(msgs), 'AI_INSUFFICIENT_CREDITS');
});

test('429 -> AI_RATE_LIMITED with Retry-After', async () => {
  const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(429, { error: { message: 'slow down' } }, { 'retry-after': '17' })));
  await assert.rejects(p.chat(msgs), (e: any) => e.code === 'AI_RATE_LIMITED' && e.retryAfterSeconds === 17 && e.httpStatus === 429);
});

test('404 / "No endpoints found" -> AI_MODEL_UNAVAILABLE', async () => {
  const p1 = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(404, { error: { message: 'nope' } })));
  await expectAi(p1.chat(msgs), 'AI_MODEL_UNAVAILABLE');
  const p2 = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(400, { error: { message: 'No endpoints found for x' } })));
  await expectAi(p2.chat(msgs), 'AI_MODEL_UNAVAILABLE');
});

test('falls back to next model when primary is rate limited / unavailable', async () => {
  const used: string[] = [];
  const p = new OpenRouterProvider(() => cfg({ OPENROUTER_MODEL: 'a', OPENROUTER_FALLBACK_MODELS: 'b, c' }), fakeFetch((_u, init) => {
    const model = JSON.parse(init.body).model; used.push(model);
    if (model === 'a') return json(429, {});
    if (model === 'b') return json(404, {});
    return json(200, { model: 'c', choices: [{ message: { content: 'from c' } }] });
  }));
  const r = await p.chat(msgs);
  assert.equal(r.content, 'from c');
  assert.deepEqual(used, ['a', 'b', 'c']);
  assert.deepEqual(r.triedModels, ['a', 'b', 'c']);
});

test('all models failing surfaces the last error', async () => {
  const p = new OpenRouterProvider(() => cfg({ OPENROUTER_FALLBACK_MODELS: 'b' }), fakeFetch(() => json(429, {})));
  await expectAi(p.chat(msgs), 'AI_RATE_LIMITED');
});

test('500 -> AI_PROVIDER_ERROR', async () => {
  const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(500, {})));
  await expectAi(p.chat(msgs), 'AI_PROVIDER_ERROR');
});

test('HTTP 200 carrying an error object is treated as an error', async () => {
  const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(200, { error: { code: 429, message: 'upstream limited' } })));
  await expectAi(p.chat(msgs), 'AI_RATE_LIMITED');
});

test('empty / malformed bodies -> AI_BAD_RESPONSE', async () => {
  for (const body of [{ choices: [] }, { choices: [{ message: { content: '  ' } }] }]) {
    const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => json(200, body)));
    await expectAi(p.chat(msgs), 'AI_BAD_RESPONSE');
  }
  const p = new OpenRouterProvider(() => cfg(), fakeFetch(() => new Response('<html>oops</html>', { status: 200 })));
  await expectAi(p.chat(msgs), 'AI_BAD_RESPONSE');
});

test('network failure -> AI_NETWORK_ERROR', async () => {
  const p = new OpenRouterProvider(() => cfg(), (() => Promise.reject(new TypeError('fetch failed'))) as any);
  await expectAi(p.chat(msgs), 'AI_NETWORK_ERROR');
});

test('real HTTP timeout -> AI_TIMEOUT', async () => {
  const server = http.createServer(() => { /* never respond */ });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    const p = new OpenRouterProvider(() => cfg({ OPENROUTER_BASE_URL: `http://127.0.0.1:${port}`, AI_TIMEOUT_MS: '1000' }));
    const t0 = Date.now();
    await expectAi(p.chat(msgs), 'AI_TIMEOUT');
    assert.ok(Date.now() - t0 < 4000);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('RateLimiter blocks after limit and reports wait', () => {
  const l = new RateLimiter(() => 2);
  assert.equal(l.take(1000), 0);
  assert.equal(l.take(2000), 0);
  assert.ok(l.take(3000) > 0);
  assert.equal(l.take(62_000), 0);
});
