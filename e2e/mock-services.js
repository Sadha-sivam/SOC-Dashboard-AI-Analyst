// Local stand-ins for Wazuh manager (55000), Wazuh Indexer (9200) and OpenRouter (4010). Test-only.
const https = require('https'), http = require('http'), fs = require('fs');
const opts = { key: fs.readFileSync(__dirname + '/key.pem'), cert: fs.readFileSync(__dirname + '/cert.pem') };
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();
let n = 0;
const docs = [];
function add(agent, msAgo, level, ruleId, description, extra = {}) {
  docs.push({ _id: `doc-${++n}`, _source: { '@timestamp': iso(msAgo), agent, rule: { id: ruleId, level, description, ...(extra.mitre ? { mitre: extra.mitre } : {}), groups: extra.groups || ['windows'] }, data: extra.data || {}, full_log: extra.full_log, decoder: { name: 'windows_eventchannel' }, location: 'EventChannel' } });
}
const win = { id: '001', name: 'win-11', ip: '192.168.252.20' };
const kali = { id: '002', name: 'kali', ip: '192.168.252.30' };
const T1110 = { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] };
const MIN = 60000, H = 3600000;
// noise over 24h
for (let i = 0; i < 140; i++) add(win, i * 10 * MIN + 3 * MIN, 3, '60106', 'Windows logon success', { data: { win: { eventdata: { targetUserName: 'bob', logonType: '2' }, system: { eventID: '4624', computer: 'win-11' } } } });
for (let i = 0; i < 30; i++) add(kali, i * 40 * MIN, 5, '5710', 'sshd: attempt to login using a non-existent user', { mitre: T1110, data: { srcip: '198.51.100.7' } });
for (let i = 0; i < 6; i++) add(kali, (i + 2) * 90 * MIN, 8, '5712', 'sshd: brute force trying to get access to the system', { mitre: T1110, data: { srcip: '198.51.100.7' } });
// incident burst on win-11 ~45 minutes ago
for (let i = 0; i < 8; i++) add(win, 45 * MIN - i * 20000, 5, '60122', 'Logon failure - Unknown user or bad password', { mitre: T1110, data: { srcip: '203.0.113.9', win: { eventdata: { targetUserName: 'alice', logonType: '3', ipAddress: '203.0.113.9', status: '0xc000006d' }, system: { eventID: '4625', computer: 'win-11' } } }, full_log: 'An account failed to log on. Account Name: alice Source Network Address: 203.0.113.9' });
add(win, 40 * MIN, 8, '60204', 'Multiple Windows logon failures', { mitre: T1110, data: { srcip: '203.0.113.9', win: { eventdata: { targetUserName: 'alice' }, system: { eventID: '4625' } } } });
add(win, 38 * MIN, 3, '60106', 'Windows logon success', { data: { win: { eventdata: { targetUserName: 'alice', logonType: '3', ipAddress: '203.0.113.9' }, system: { eventID: '4624', computer: 'win-11' } } }, full_log: 'An account was successfully logged on. alice from 203.0.113.9' });
add(win, 37 * MIN, 12, '92027', 'Suspicious PowerShell encoded command executed', { mitre: { id: ['T1059.001'], tactic: ['Execution'], technique: ['PowerShell'] }, groups: ['sysmon'], data: { win: { eventdata: { image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', commandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA password=Summer2026! C:\\Users\\alice\\x.ps1', parentImage: 'C:\\Windows\\explorer.exe', subjectUserName: 'alice' }, system: { eventID: '1', computer: 'win-11' } } }, full_log: 'powershell -enc SQBF... user alice host win-11' });
add(win, 36 * MIN, 10, '554', 'File added to the system', { groups: ['syscheck'], data: {} });
docs.sort((a, b) => a._source['@timestamp'].localeCompare(b._source['@timestamp']));

const sevKey = (l) => (l >= 12 ? 'critical' : l >= 10 ? 'high' : l >= 7 ? 'medium' : l >= 4 ? 'low' : 'info');

function search(body) {
  if (body.size === 0 && body.aggs) {
    const sevCounts = {}; const trend = new Map(); const agents = new Map(); const rules = new Map();
    for (const d of docs) {
      const l = d._source.rule.level, k = sevKey(l); sevCounts[k] = (sevCounts[k] || 0) + 1;
      const t = new Date(d._source['@timestamp']); t.setMinutes(0, 0, 0);
      const b = trend.get(t.getTime()) || { c: 0, crit: 0, high: 0 }; b.c++; if (l >= 12) b.crit++; if (l >= 10 && l < 12) b.high++; trend.set(t.getTime(), b);
      const a = agents.get(d._source.agent.id) || { n: d._source.agent.name, c: 0 }; a.c++; agents.set(d._source.agent.id, a);
      const r = rules.get(d._source.rule.id) || { c: 0, s: d._source.rule }; r.c++; rules.set(d._source.rule.id, r);
    }
    return { hits: { total: { value: docs.length, relation: 'eq' }, hits: [] }, aggregations: {
      severity: { buckets: Object.entries(sevCounts).map(([key, doc_count]) => ({ key, doc_count })) },
      trend: { buckets: [...trend.entries()].sort((a, b) => a[0] - b[0]).map(([k, v]) => ({ key: k, key_as_string: new Date(k).toISOString(), doc_count: v.c, critical: { doc_count: v.crit }, high: { doc_count: v.high } })) },
      agents: { buckets: [...agents.entries()].map(([key, v]) => ({ key, doc_count: v.c, name: { buckets: [{ key: v.n }] } })) },
      rules: { buckets: [...rules.entries()].sort((a, b) => b[1].c - a[1].c).slice(0, 8).map(([key, v]) => ({ key, doc_count: v.c, sample: { hits: { hits: [{ _source: { rule: v.s } }] } } })) },
    } };
  }
  if (body.query && body.query.ids) return { hits: { hits: docs.filter((d) => body.query.ids.values.includes(d._id)) } };
  let r = docs;
  const q = body.query || {};
  const filters = q.bool ? q.bool.filter : [q];
  for (const f of filters) {
    if (f.range && f.range['@timestamp']) { const g = f.range['@timestamp']; r = r.filter((d) => { const t = d._source['@timestamp']; return (!g.gt || t > g.gt) && (!g.lte || t <= g.lte); }); }
    if (f.term && f.term['agent.id']) r = r.filter((d) => d._source.agent.id === f.term['agent.id']);
    if (f.range && f.range['rule.level']) r = r.filter((d) => d._source.rule.level >= (f.range['rule.level'].gte || 0));
  }
  const order = body.sort && body.sort[0]['@timestamp'].order;
  r = [...r].sort((a, b) => a._source['@timestamp'].localeCompare(b._source['@timestamp']) * (order === 'desc' ? -1 : 1));
  return { hits: { hits: r.slice(0, body.size || 10) } };
}
const readBody = (req) => new Promise((res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => res(b ? JSON.parse(b) : {})); });

https.createServer(opts, async (req, res) => {
  const body = await readBody(req);
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(search(body)));
}).listen(9200);

https.createServer(opts, (req, res) => {
  res.setHeader('content-type', 'application/json');
  if (req.url.startsWith('/security/user/authenticate')) return res.end(JSON.stringify({ data: { token: 'tok' } }));
  if (req.url.startsWith('/agents')) return res.end(JSON.stringify({ data: { affected_items: [
    { id: '000', name: 'wazuh-manager', ip: '127.0.0.1', status: 'active', os: { name: 'Ubuntu', version: '22.04' } },
    { id: '001', name: 'win-11', ip: '192.168.252.20', status: 'active', os: { name: 'Microsoft Windows 11 Pro', version: '10.0.22631' } },
    { id: '002', name: 'kali', ip: '192.168.252.30', status: 'disconnected', os: { name: 'Kali GNU/Linux', version: '2024.3' } } ] } }));
  res.end('{}');
}).listen(55000);

// Stand-in for OpenRouter. Echoes placeholders it finds in the (masked) evidence so un-masking can be verified.
let calls = 0;
http.createServer(async (req, res) => {
  const body = await readBody(req);
  const last = body.messages[body.messages.length - 1].content;
  fs.appendFileSync(__dirname + '/openrouter-requests.log', JSON.stringify({ auth: req.headers.authorization, model: body.model, messages: body.messages }) + '\n');
  res.setHeader('content-type', 'application/json');
  if (/RATELIMIT/.test(last)) { res.statusCode = 429; res.setHeader('retry-after', '42'); return res.end(JSON.stringify({ error: { message: 'rate limited' } })); }
  if (/MODELGONE/.test(last)) { res.statusCode = 404; return res.end(JSON.stringify({ error: { message: 'no such model' } })); }
  if (/SLOW/.test(last)) return; // never answers -> timeout
  calls++;
  const ev = body.messages[1].content;
  const ip = (ev.match(/EXTERNAL_IP_\d+/) || ['(none)'])[0], user = (ev.match(/USER_\d+/) || ['(none)'])[0], host = (ev.match(/HOST_\d+/) || ['(none)'])[0];
  const text = `## Executive summary\nRepeated logon failures for **${user}** from \`${ip}\` on ${host} were followed by a successful logon and an encoded PowerShell command. This is *consistent with* credential guessing, but it is **not confirmed**.\n\n## Supporting evidence\n- **Observed:** several Windows 4625 events (rule \`60122\`) from ${ip}\n- **Observed:** rule \`92027\` encoded PowerShell, level 12\n- **Hypothesis:** the successful logon may be the same actor\n\n## Event timeline\n| Time | Event |\n|---|---|\n| T-45m | Logon failures begin |\n| T-38m | Logon success |\n| T-37m | Encoded PowerShell |\n\n## Confidence\nMedium. Only a capped sample was provided.\n\n_AI-generated analysis from limited evidence. A human analyst must verify before any conclusion or action._ (call ${calls})`;
  res.end(JSON.stringify({ model: body.model, choices: [{ message: { role: 'assistant', content: text } }], usage: { prompt_tokens: 1000, completion_tokens: 200, total_tokens: 1200 } }));
}).listen(4010);
console.log('mocks up');
