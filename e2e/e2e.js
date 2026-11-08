const { chromium } = require('playwright');
const SP = process.argv[2];
const FE = 'http://127.0.0.1:4173';
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => m.type() === 'error' && errors.push('console: ' + m.text()));
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  const shot = (n) => page.screenshot({ path: `${SP}/shots/${n}.png` });
  const results = [];
  const ok = (name, cond) => { results.push([name, !!cond]); console.log((cond ? 'PASS ' : 'FAIL ') + name); };
  const step = async (name, fn) => { try { await fn(); } catch (e) { ok(name + ' [exception: ' + e.message.split('\n')[0] + ']', false); await shot('fail-' + results.length).catch(() => {}); } };

  await step('overview', async () => {
    await page.goto(FE + '/'); await page.waitForSelector('text=Total raw alerts'); await page.waitForTimeout(1800);
    ok('overview: exact total 188 shown', await page.locator('text=188').first().isVisible());
    ok('overview: trend chart rendered', (await page.locator('svg.recharts-surface').count()) > 0);
    ok('overview: recent activity lists alerts', await page.locator('text=Recent security activity').isVisible());
    await shot('01-overview');
  });

  await step('alert queue', async () => {
    await page.click('nav >> text=Alert Queue'); await page.waitForSelector('tbody tr'); await page.waitForTimeout(500);
    await page.fill('input[placeholder^="Search"]', 'PowerShell');
    ok('alerts: search filters to PowerShell rows', (await page.locator('tbody tr').count()) === 1);
    await page.locator('tbody tr').first().click(); await page.waitForSelector('[role=dialog]');
    await page.waitForSelector('text=Wazuh MITRE mapping');
    ok('alerts: drawer shows MITRE mapping', await page.locator('text=T1059.001').first().isVisible());
    await shot('02-alert-drawer');
    await page.keyboard.press('Escape'); await page.fill('input[placeholder^="Search"]', '');
    await page.selectOption('select[aria-label="Severity filter"]', 'CRITICAL');
    ok('alerts: severity filter -> 1 critical row', (await page.locator('tbody tr').count()) === 1);
    await page.selectOption('select[aria-label="Severity filter"]', 'ALL');
    await page.click('th >> text=Severity'); await page.waitForTimeout(200);
    ok('alerts: sort by severity puts critical first', /Critical/i.test(await page.locator('tbody tr').first().innerText()));
  });

  await step('handoff', async () => {
    await page.fill('input[placeholder^="Search"]', 'PowerShell'); await page.locator('tbody tr').first().click(); await page.waitForSelector('[role=dialog]');
    await page.click('text=Explain with AI Analyst'); await page.waitForSelector('h1:has-text("AI Analyst")');
    ok('ai: context chip shows selected alert', await page.locator('text=/Alert: Suspicious PowerShell/').first().isVisible());
    ok('ai: shows configured model pill', await page.locator('text=model:free').first().isVisible());
    await shot('03-ai-empty');
  });

  await step('restriction', async () => {
    await page.goto(FE + '/alerts'); await page.waitForSelector('tbody tr');
    await page.fill('input[placeholder^="Search"]', 'non-existent user'); await page.locator('tbody tr').first().click(); await page.waitForSelector('[role=dialog]');
    ok('alerts: AI button disabled for non-001 agent', await page.locator('button:has-text("Explain with AI Analyst")').isDisabled());
    ok('alerts: restriction explained', await page.locator('text=restricted to agent 001').isVisible());
  });

  await step('chat', async () => {
    await page.goto(FE + '/ai-analyst'); await page.waitForSelector('h1:has-text("AI Analyst")');
    await page.click('text=Build an attack timeline'); await page.waitForSelector('text=Executive summary', { timeout: 15000 });
    ok('ai: reply rendered with headings', await page.locator('[role=heading]:has-text("Executive summary")').first().isVisible());
    ok('ai: table rendered', (await page.locator('table').count()) > 0);
    const body = await page.locator('main').innerText();
    ok('ai: reply un-masked to real values', body.includes('alice') && body.includes('203.0.113.9') && !/USER_\d|EXTERNAL_IP_\d/.test(body));
    ok('ai: evidence footprint shown', await page.locator('text=/Based on \\d+ of \\d+ alerts/').first().isVisible());
    await shot('04-ai-answer');
    await page.fill('textarea', 'Why might this be a false positive?'); await page.keyboard.press('Enter');
    await page.waitForFunction(() => document.querySelectorAll('[role=heading]').length > 5, null, { timeout: 15000 });
    ok('ai: follow-up answered', (await page.locator('li:has-text("Why might this be a false positive?")').count()) >= 1);
  });

  await step('errors', async () => {
    await page.fill('textarea', 'RATELIMIT test'); await page.keyboard.press('Enter'); await page.waitForSelector('[role=alert]:has-text("Rate limit reached")');
    ok('ai: rate limit message with retry time', await page.locator('text=/about 42s/').first().isVisible());
    await shot('05-ai-ratelimit');
    await page.fill('textarea', 'MODELGONE test'); await page.keyboard.press('Enter'); await page.waitForSelector('text=/is unavailable/');
    ok('ai: unavailable-model error shown', true);
    await page.fill('textarea', 'SLOW test'); await page.keyboard.press('Enter'); await page.waitForSelector('text=/did not respond within/', { timeout: 10000 });
    ok('ai: timeout error shown, composer usable again', await page.locator('button[aria-label="Send message"]').isVisible());
  });

  await step('persistence', async () => {
    await page.reload(); await page.waitForSelector('[role=heading]:has-text("Executive summary")');
    ok('ai: conversation restored after reload', true);
    await page.click('text=New conversation'); await page.waitForSelector('text=How can I help');
    ok('ai: new conversation shows suggestions', await page.locator('text=Explain this security alert').isVisible());
    ok('ai: multiple conversations listed', (await page.locator('nav[aria-label=Conversations] > div').count()) >= 2);
  });

  await step('preview', async () => {
    await page.click('button[aria-label="Preview evidence sent to AI provider"]'); await page.waitForSelector('text=Evidence sent to the AI provider'); await page.waitForSelector('pre');
    await page.waitForTimeout(400);
    const pre = await page.locator('pre').innerText();
    ok('ai: evidence preview is masked', !/203\.0\.113\.9|alice|win-11/.test(pre) && /EXTERNAL_IP_1/.test(pre));
    await shot('06-ai-preview'); await page.keyboard.press('Escape');
  });

  await step('investigations', async () => {
    await page.goto(FE + '/incidents'); await page.waitForSelector('tbody tr');
    const n = await page.locator('tbody tr').count();
    ok('investigations: groups listed', n > 0);
    let found = false;
    for (let i = 0; i < n && !found; i++) {
      await page.goto(FE + '/incidents'); await page.waitForSelector('tbody tr');
      await page.locator('tbody tr').nth(i).click(); await page.waitForSelector('text=Event timeline');
      if (await page.locator('text=Suspicious PowerShell').count()) found = true;
    }
    ok('investigation: detail with PowerShell group found', found);
    await page.selectOption('#status', 'INVESTIGATING'); await page.fill('#notes', 'Reviewing logon source.');
    await page.reload(); await page.waitForSelector('#notes');
    ok('investigation: status + notes persisted locally', (await page.inputValue('#notes')) === 'Reviewing logon source.' && (await page.inputValue('#status')) === 'INVESTIGATING');
    await shot('07-investigation');
    await page.click('text=Analyse with AI'); await page.waitForSelector('h1:has-text("AI Analyst")');
    ok('investigation -> AI: investigation context chip', await page.locator('text=/Investigation:/').first().isVisible());
  });

  await step('legacy', async () => {
    for (const [path, text] of [['/stories', 'Attack'], ['/endpoints', 'Endpoint'], ['/mitre', 'MITRE'], ['/settings', 'Settings']]) {
      await page.goto(FE + path); await page.waitForTimeout(1500);
      ok(`legacy page ${path} renders`, (await page.locator('main').first().innerText()).includes(text));
    }
  });

  await step('mobile', async () => {
    const m = await browser.newContext({ viewport: { width: 390, height: 800 } }); const mp = await m.newPage();
    await mp.goto(FE + '/'); await mp.waitForSelector('text=Total raw alerts'); await mp.waitForTimeout(1500);
    ok('mobile: no horizontal page scroll (overview)', await mp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
    ok('mobile: nav strip visible', await mp.locator('nav[aria-label=Primary]').isVisible());
    await mp.screenshot({ path: `${SP}/shots/08-mobile-overview.png` });
    await mp.goto(FE + '/ai-analyst'); await mp.waitForSelector('textarea'); await mp.waitForTimeout(500);
    ok('mobile: ai page no horizontal scroll', await mp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
    await mp.screenshot({ path: `${SP}/shots/09-mobile-ai.png` });
  });

  console.log('\nconsole/page errors:', errors.length ? errors : 'none');
  console.log(`\n${results.filter((r) => r[1]).length}/${results.length} checks passed`);
  await browser.close();
})();
