/**
 * Reversible pseudonymisation applied before any text leaves the backend for an
 * external AI provider.
 *
 *  - IPs, e-mail addresses, MAC addresses, known usernames and hostnames are
 *    replaced with stable placeholders (INTERNAL_IP_1, USER_2, HOST_1 ...). The
 *    same value always maps to the same placeholder within one request, so the
 *    model can still reason about "the same source IP".
 *  - Secrets (passwords, tokens, API keys, long hex/base64 blobs) are replaced
 *    with [REDACTED] and are NOT reversible.
 *  - The model's reply is un-masked locally so the analyst sees real values.
 */

export type MaskKind = 'internalIp' | 'externalIp' | 'email' | 'mac' | 'user' | 'host' | 'secret';

const SYSTEM_ACCOUNTS = new Set(
  [
    'system',
    'local service',
    'network service',
    'anonymous logon',
    'window manager',
    '-',
    'n/a',
    'root',
    'nt authority',
    'nt authority\\system',
  ].map((s) => s.toLowerCase()),
);

function isSystemAccount(name: string): boolean {
  const n = name.trim().toLowerCase();
  return SYSTEM_ACCOUNTS.has(n) || /^dwm-\d+$/.test(n) || /^umfd-\d+$/.test(n) || /\$$/.test(n);
}

function isPrivateIpv4(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const IPV6 = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
// key=value / key: value secrets
const KEYED_SECRET =
  /\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|authorization|credential)s?\b(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const LONG_HEX = /\b[a-fA-F0-9]{40,}\b/g;
const LONG_B64 = /\b[A-Za-z0-9+/_-]{48,}={0,2}\b/g;
const WIN_PROFILE = /([A-Za-z]:\\Users\\)([^\\\s"']+)/gi;
const NIX_HOME = /(\/home\/)([^/\s"']+)/g;

export class Masker {
  private forward = new Map<string, string>(); // "kind:value" -> placeholder
  private reverse = new Map<string, string>(); // placeholder -> value
  private counters: Record<string, number> = {};
  private stats: Record<MaskKind, number> = {
    internalIp: 0,
    externalIp: 0,
    email: 0,
    mac: 0,
    user: 0,
    host: 0,
    secret: 0,
  };
  private knownUsers: string[] = [];
  private knownHosts: string[] = [];

  private placeholder(prefix: string, kind: MaskKind, value: string): string {
    const key = `${prefix}:${value.toLowerCase()}`;
    const existing = this.forward.get(key);
    if (existing) return existing;
    this.counters[prefix] = (this.counters[prefix] ?? 0) + 1;
    const ph = `${prefix}_${this.counters[prefix]}`;
    this.forward.set(key, ph);
    this.reverse.set(ph, value);
    this.stats[kind]++;
    return ph;
  }

  /** Register a username so that every occurrence in free text is masked. */
  registerUser(name: unknown): void {
    if (typeof name !== 'string') return;
    const v = name.trim();
    if (v.length < 2 || isSystemAccount(v)) return;
    if (!this.knownUsers.includes(v)) this.knownUsers.push(v);
  }

  registerHost(name: unknown): void {
    if (typeof name !== 'string') return;
    const v = name.trim();
    if (v.length < 2) return;
    if (!this.knownHosts.includes(v)) this.knownHosts.push(v);
  }

  private escape(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  mask(text: string): string {
    if (!text) return text;
    let out = text;

    // 1. Secrets first so we never treat a secret as a hostname/user etc.
    out = out.replace(JWT, () => {
      this.stats.secret++;
      return '[REDACTED]';
    });
    out = out.replace(BEARER, () => {
      this.stats.secret++;
      return 'Bearer [REDACTED]';
    });
    out = out.replace(KEYED_SECRET, (_m, key: string, sep: string) => {
      this.stats.secret++;
      return `${key}${sep}[REDACTED]`;
    });
    out = out.replace(LONG_HEX, () => {
      this.stats.secret++;
      return '[REDACTED]';
    });
    out = out.replace(LONG_B64, (m) => {
      // Only treat mixed-case alphanumeric blobs as secrets, not long file paths.
      if (!(/[A-Z]/.test(m) && /[a-z]/.test(m) && /\d/.test(m))) return m;
      this.stats.secret++;
      return '[REDACTED]';
    });

    // 2. Profile paths (C:\Users\alice, /home/alice)
    out = out.replace(WIN_PROFILE, (_m, pre: string, name: string) =>
      isSystemAccount(name) || /^(public|default|all users)$/i.test(name)
        ? `${pre}${name}`
        : `${pre}${this.placeholder('USER', 'user', name)}`,
    );
    out = out.replace(NIX_HOME, (_m, pre: string, name: string) =>
      `${pre}${this.placeholder('USER', 'user', name)}`,
    );

    // 3. E-mail before usernames/hosts so the local part is not split up
    out = out.replace(EMAIL, (m) => this.placeholder('EMAIL', 'email', m));
    out = out.replace(MAC, (m) => this.placeholder('MAC', 'mac', m));

    // 4. IPs
    out = out.replace(IPV4, (m) =>
      isPrivateIpv4(m)
        ? this.placeholder('INTERNAL_IP', 'internalIp', m)
        : this.placeholder('EXTERNAL_IP', 'externalIp', m),
    );
    out = out.replace(IPV6, (m) => this.placeholder('EXTERNAL_IP', 'externalIp', m));

    // 5. Known hostnames and usernames (longest first)
    for (const h of [...this.knownHosts].sort((a, b) => b.length - a.length)) {
      out = out.replace(new RegExp(`(?<![A-Za-z0-9_-])${this.escape(h)}(?![A-Za-z0-9_-])`, 'gi'), () =>
        this.placeholder('HOST', 'host', h),
      );
    }
    for (const u of [...this.knownUsers].sort((a, b) => b.length - a.length)) {
      out = out.replace(new RegExp(`(?<![A-Za-z0-9_-])${this.escape(u)}(?![A-Za-z0-9_-])`, 'gi'), () =>
        this.placeholder('USER', 'user', u),
      );
    }
    return out;
  }

  /** Mask every string inside a JSON-like value. Object keys are left intact. */
  maskDeep<T>(value: T): T {
    if (typeof value === 'string') return this.mask(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => this.maskDeep(v)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = this.maskDeep(v);
      return out as T;
    }
    return value;
  }

  /** Restore original values in model output. [REDACTED] stays redacted. */
  unmask(text: string): string {
    if (!text || this.reverse.size === 0) return text;
    const placeholders = [...this.reverse.keys()].sort((a, b) => b.length - a.length);
    const re = new RegExp(`(?<![A-Za-z0-9_])(${placeholders.map((p) => this.escape(p)).join('|')})(?![A-Za-z0-9_])`, 'g');
    return text.replace(re, (m) => this.reverse.get(m) ?? m);
  }

  summary(): Record<MaskKind, number> & { total: number } {
    const total = Object.values(this.stats).reduce((a, b) => a + b, 0);
    return { ...this.stats, total };
  }
}
