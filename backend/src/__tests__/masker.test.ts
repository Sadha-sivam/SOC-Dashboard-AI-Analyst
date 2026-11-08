import test from 'node:test';
import assert from 'node:assert/strict';
import { Masker } from '../ai/Masker';

test('masks internal/external IPs consistently and reversibly', () => {
  const m = new Masker();
  const out = m.mask('from 203.0.113.9 to 192.168.1.5, again 203.0.113.9');
  assert.equal(out, 'from EXTERNAL_IP_1 to INTERNAL_IP_1, again EXTERNAL_IP_1');
  assert.equal(m.unmask('EXTERNAL_IP_1 hit INTERNAL_IP_1'), '203.0.113.9 hit 192.168.1.5');
});

test('masks emails, MACs, registered users and hosts but keeps system accounts', () => {
  const m = new Masker();
  m.registerUser('alice');
  m.registerUser('SYSTEM');
  m.registerHost('win-11');
  const out = m.mask('alice@corp.example logged on win-11 as alice and SYSTEM mac 00:1A:2B:3C:4D:5E');
  assert.ok(!/alice|corp\.example|win-11|00:1A/i.test(out), out);
  assert.match(out, /SYSTEM/);
  assert.equal(m.unmask(out), 'alice@corp.example logged on win-11 as alice and SYSTEM mac 00:1A:2B:3C:4D:5E');
});

test('redacts secrets irreversibly and does not eat ordinary words', () => {
  const m = new Masker();
  const out = m.mask('password=hunter2 token: abc123 Authorization: Bearer abcdefghijklmnop1234 password for the user failed');
  assert.ok(!out.includes('hunter2') && !out.includes('abc123') && !out.includes('abcdefghijklmnop1234'), out);
  assert.match(out, /password for the user failed/);
  assert.ok(m.unmask(out).includes('[REDACTED]'));
  assert.ok(m.summary().secret >= 3);
});

test('redacts JWT and long hex but leaves long paths alone', () => {
  const m = new Masker();
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstu';
  const path = '/usr/lib/python3/dist-packages/something/very/long/path/to/some/module/file.py';
  const out = m.mask(`${jwt} ${'a1'.repeat(30)} ${path}`);
  assert.ok(!out.includes('eyJhbGci') && !out.includes('a1a1a1a1a1'));
  assert.ok(out.includes(path));
});

test('masks Windows profile paths and deep objects', () => {
  const m = new Masker();
  const out = m.maskDeep({ p: 'C:\\Users\\bob\\Desktop\\x.exe', n: [1, '10.0.0.7'], k: true });
  assert.equal(out.p, 'C:\\Users\\USER_1\\Desktop\\x.exe');
  assert.deepEqual(out.n, [1, 'INTERNAL_IP_1']);
  assert.equal(out.k, true);
});

test('unmask does not touch similar-looking text', () => {
  const m = new Masker();
  m.mask('1.2.3.4');
  assert.equal(m.unmask('XEXTERNAL_IP_1 EXTERNAL_IP_10'), 'XEXTERNAL_IP_1 EXTERNAL_IP_10');
});
