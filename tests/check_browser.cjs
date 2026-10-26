// Use the installed Playwright and Chromium via PLAYWRIGHT_MODULE and CHROMIUM_PATH.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { createHash } = require('node:crypto');
const root = path.resolve(__dirname, '..');
const htmlArg = process.argv.indexOf('--html');
const htmlFile = htmlArg === -1 ? 'index.html' : process.argv[htmlArg + 1];
const prefix = htmlFile === 'index.html' ? 'testing' : 'testing-preview';
const url = pathToFileURL(path.join(root, htmlFile)).href;
const categories = ['osint', 'reversing', 'forensics', 'crypto', 'misc', 'web', 'malware'];
const noteSources = ['CORE_WORKFLOWS.md', 'SPECIALIST_WORKFLOWS.md', 'CTF_CHEATSHEET.md', 'HASHCAT.md', 'LEARNING_RESOURCES.md', 'PRACTICE_WORKSHEETS.md', 'APPROVED_TOOL_REFERENCES.md', 'EVENT_SOURCES.md', 'RESOURCE_EVALUATION.md', 'research/learning/practice/README.md', 'research/learning/video-coverage/practice/TRIAGE_PRACTICE.md', 'research/learning/video-coverage/practice/AUDIO_PRACTICE.md'];
const noteOutputs = Object.fromEntries(noteSources.map(name => [name, name.replace(/\.md$/, '.html')]));
noteOutputs['examples/core/README.md'] = 'CORE_PRACTICE.html';
noteSources.push('examples/core/README.md');
noteOutputs['scripts/templates/README.md'] = 'TEMPLATES.html';
noteSources.push('scripts/templates/README.md');
noteOutputs['scripts/README.md'] = 'TOOLKIT.html';
noteOutputs['scripts/chatbot_strategies.md'] = 'CHATBOT_STRATEGIES.html';
noteOutputs['docs/public-rules.md'] = 'RULES.html';
noteSources.push('scripts/README.md', 'scripts/chatbot_strategies.md', 'docs/public-rules.md');
const noteFiles = ['build_notes.py', 'notes-template.html', ...noteSources, ...Object.values(noteOutputs)];
const noteHashes = () => Object.fromEntries(noteFiles.map(name => [name, createHash('sha256').update(fs.readFileSync(path.join(root, name))).digest('hex')]));
const visibleTools = page => page.locator('[data-source-ids]:visible');
async function unobscured(page, locator, label) {
  // Fragment revelation schedules scrolling on the next animation frame.
  await locator.evaluate(node => new Promise((resolve, reject) => {
    const deadline = performance.now() + 3000;
    function check() {
      const box = node.getBoundingClientRect();
      const nav = document.querySelector('nav').getBoundingClientRect();
      if (box.y >= nav.bottom - 1 && box.y < innerHeight) return resolve();
      if (performance.now() > deadline) return reject(new Error('Fragment did not settle below navigation'));
      requestAnimationFrame(check);
    }
    check();
  }));
  const box = await locator.boundingBox();
  const nav = await page.locator('nav').boundingBox();
  assert(box && box.y >= nav.y + nav.height - 1, `sticky nav obscures ${label}`);
}
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH });
  const htmlHash = () => createHash('sha256').update(fs.readFileSync(path.join(root, htmlFile))).digest('hex');
  const report = { checked_at: new Date().toISOString(), html_file: htmlFile, html_sha256: htmlHash(), browser: browser.version(), notes_sha256: noteHashes(), cases: [] };
  try {
    for (const [width, height] of [[320, 900], [390, 900], [768, 900], [1440, 900], [667, 375]]) {
      const page = await browser.newPage({ viewport: { width, height }, reducedMotion: 'reduce' });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', route => /^https?:/.test(route.request().url()) ? route.abort() : route.continue());
      await page.context().setOffline(true);
      await page.goto(url);
      const initialSearch = page.locator('#tool-search');
      const searchBox = await initialSearch.boundingBox();
      assert(searchBox && searchBox.y >= 0 && searchBox.y + searchBox.height <= height,
        `tool search requires scrolling at ${width}×${height}`);
      const toolsNav = await page.locator('nav a[href="#tools"]').boundingBox();
      assert(toolsNav && toolsNav.x >= 0 && toolsNav.x + toolsNav.width <= width,
        `tools navigation is off-screen at ${width}`);
      const coreLink = await page.locator('#tools a[href="CORE_WORKFLOWS.html"]').boundingBox();
      assert(coreLink && coreLink.y >= 0 && coreLink.y + coreLink.height < height,
        `core workflows link requires scrolling at ${width}×${height}`);
      const rules = page.locator('details.rules');
      await rules.locator('summary').focus();
      await page.keyboard.press('Enter');
      assert(await rules.locator('p').isVisible(), 'competition rules cannot be expanded');
      await page.keyboard.press('Enter');
      assert.equal(await page.locator('.proposal').count(), 32);
      for (const catalog of await page.locator('details.catalog').all()) {
        const origins = await catalog.locator('.catalog-tool').evaluateAll(nodes => nodes.map(n => n.dataset.origin));
        const firstOther = origins.findIndex(origin => origin !== 'TrendMicro proposal');
        if (firstOther !== -1) assert(!origins.slice(firstOther).includes('TrendMicro proposal'), 'proposal ordering changed');
      }
      const details = page.locator('details.catalog');
      assert.equal(await details.count(), 7);
      for (let i = 0; i < 7; i++) {
        const summary = details.nth(i).locator(':scope > summary');
        await summary.focus();
        await page.keyboard.press('Enter');
        assert.equal(await details.nth(i).evaluate(node => node.open), true);
      }
      assert.equal(await visibleTools(page).count(), 200);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `expanded catalog overflow at ${width}`);
      const search = page.getByRole('searchbox', { name: 'Find an approved tool', exact: true });
      // Search a specialist tool that is not a starting-route shortcut.
      const specialist = page.locator('[data-source-ids]').filter({ has: page.locator('h3', { hasText: /Chainsaw/ }) }).first();
      const specialistId = await specialist.getAttribute('data-source-ids');
      for (const query of ['cHaInSaW', specialistId]) {
        await search.fill(query);
        assert(await specialist.isVisible(), `specialist not found: ${query}`);
        assert((await visibleTools(page).count()) > 0);
        const matches = await visibleTools(page).evaluateAll(nodes => nodes.every(node => node.dataset.search.toLowerCase().includes(document.querySelector('#tool-search').value.toLowerCase())));
        assert(matches, 'filter exposes nonmatching entries');
        assert((await page.locator('#tool-count').innerText()).includes(String(await visibleTools(page).count())));
      }
      await search.fill('zzzz-no-approved-tool-matches-zzzz');
      assert.equal(await visibleTools(page).count(), 0);
      assert(await page.locator('#no-results').isVisible());
      if (width === 390) await page.screenshot({ path: path.join(root, `research/${prefix}-empty.png`) });
      await page.locator('#clear-search').click();
      assert.equal(await search.inputValue(), '');
      assert.equal(await page.locator('[data-source-ids][hidden]').count(), 0);
      assert.equal(await page.locator('#no-results').isVisible(), false);
      // Every route's authored instructions remain usable with all networking disabled.
      const routes = page.locator('details.task-route');
      assert.equal(await routes.count(), 33);
      for (let i = 0; i < 33; i++) {
        const route = routes.nth(i);
        await route.locator(':scope > summary').focus();
        await page.keyboard.press('Space');
        assert(await route.locator('ol.steps').isVisible());
        assert((await route.locator('ol.steps > li').count()) > 0);
        for (const field of ['expected', 'fallback', 'caveat']) assert((await route.locator(`.${field}`).innerText()).trim());
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `expanded route overflow at ${width}`);
      // A route link must recover a target hidden by both a closed catalog and a conflicting filter.
      const toolLink = routes.first().locator('a[href^="#tool-"]').first();
      const fragment = await toolLink.getAttribute('href');
      await search.fill('zzzz-no-approved-tool-matches-zzzz');
      await details.evaluateAll(nodes => nodes.forEach(node => { node.open = false; }));
      await toolLink.click();
      const target = page.locator(fragment);
      await target.waitFor({ state: 'visible', timeout: 3000 });
      assert(await target.isVisible(), 'tool link did not reveal filtered/collapsed target');
      await unobscured(page, target, fragment);
      await page.goto(url + fragment);
      await page.locator(fragment).waitFor({ state: 'visible', timeout: 3000 });
      assert(await page.locator(fragment).isVisible(), 'direct fragment load did not reveal tool');
      await unobscured(page, page.locator(fragment), 'initial fragment');
      for (const id of categories) {
        const link = page.locator(`nav a[href="#${id}"]`);
        await link.focus();
        await page.keyboard.press('Enter');
        assert.equal(await page.evaluate(() => location.hash), `#${id}`);
        await unobscured(page, page.locator(`#${id}`), `${id} at ${width}`);
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow at ${width}`);
      await page.locator('nav a[href="#forensics"]').click();
      if ([390, 1440].includes(width)) await page.screenshot({ path: path.join(root, `research/${prefix}-${width}.png`) });
      assert.deepEqual(errors, []);
      report.cases.push({ width, height, offline_routes: 33, initial_search_visible: 'pass', tools_navigation_visible: 'pass', rules_keyboard_expansion: 'pass', filter_success_empty_reset: 'pass', tool_fragments: 'pass', overflow: 'pass', navigation: 'pass', page_errors: errors });
      await page.close();
    }
    const notes = await browser.newPage({ viewport: { width: 320, height: 900 } });
    const noteErrors = [];
    notes.on('pageerror', error => noteErrors.push(error.message));
    await notes.context().setOffline(true);
    await notes.goto(url);
    await notes.locator('a[href="LEARNING_RESOURCES.html"]').click();
    await notes.waitForURL('**/LEARNING_RESOURCES.html');
    assert(notes.url().endsWith('/LEARNING_RESOURCES.html'));
    assert.equal(await notes.locator('main h1').count(), 1, 'preparation was rendered as raw text');
    assert((await notes.locator('main a').count()) > 0);
    await notes.locator('a[href="PRACTICE_WORKSHEETS.html#block-2"]').click();
    await notes.waitForURL('**/PRACTICE_WORKSHEETS.html#block-2');
    assert(notes.url().endsWith('/PRACTICE_WORKSHEETS.html#block-2'));
    const block = notes.locator('#block-2');
    assert.equal(await block.count(), 1);
    const position = await block.boundingBox();
    assert(position && position.y >= 0 && position.y < 900, 'worksheet fragment not reached');
    const back = notes.locator('header a[href="index.html"]');
    await back.focus();
    assert(await back.evaluate(node => node === document.activeElement));
    await notes.keyboard.press('Enter');
    await notes.waitForURL('**/index.html');
    assert(notes.url().endsWith('/index.html'));
    // Exercise every published note at the narrowest supported viewport.
    let scrollableTables = 0;
    for (const source of noteSources) {
      const file = noteOutputs[source];
      await notes.goto(pathToFileURL(path.join(root, file)).href);
      assert.equal(await notes.locator('main h1').count(), 1);
      assert.equal(await notes.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `notes overflow: ${file}`);
      const tables = notes.locator('.table-scroll');
      for (let i = 0; i < await tables.count(); i++) {
        const table = tables.nth(i);
        await table.focus();
        assert(await table.evaluate(node => node === document.activeElement && getComputedStyle(node).overflowX === 'auto'));
        if (await table.evaluate(node => node.scrollWidth > node.clientWidth)) {
          const before = await table.evaluate(node => node.scrollLeft);
          await notes.keyboard.press('ArrowRight');
          await table.evaluate(node => new Promise((resolve, reject) => {
            const deadline = performance.now() + 2000;
            function check() {
              if (node.scrollLeft > 0) return resolve();
              if (performance.now() > deadline) return reject(new Error('Table did not scroll with keyboard'));
              requestAnimationFrame(check);
            }
            check();
          }));
          assert((await table.evaluate(node => node.scrollLeft)) > before);
          scrollableTables++;
        }
      }
    }
    assert(scrollableTables > 0, 'narrow table scrolling was not exercised');
    // Toolkit links and prose must remain usable offline at phone, desktop and short landscape sizes.
    for (const [width, height] of [[320, 900], [1440, 900], [667, 375]]) {
      await notes.setViewportSize({ width, height });
      await notes.goto(url);
      await notes.locator('a[href="TOOLKIT.html"]').click();
      await notes.waitForURL('**/TOOLKIT.html');
      assert.equal(await notes.locator('#setup').count(), 1);
      assert.equal(await notes.locator('a[href="scripts/ctf.py"]').count(), 1);
      assert.equal(await notes.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `toolkit overflow at ${width}`);
      await notes.locator('a[href="RULES.html"]').click();
      await notes.waitForURL('**/RULES.html');
      assert.equal(await notes.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `rules overflow at ${width}`);
      await notes.locator('a[href="TOOLKIT.html#setup"]').focus();
      await notes.keyboard.press('Enter');
      await notes.waitForURL('**/TOOLKIT.html#setup');
      assert.equal(await notes.locator('#setup').count(), 1);
      if (width === 320) await notes.screenshot({ path: path.join(root, `research/${prefix}-toolkit-320.png`) });
    }
    report.toolkit_navigation = 'guide → toolkit → rules → toolkit setup, offline at 320, 1440 and 667×375';
    await notes.setViewportSize({ width: 320, height: 900 });
    assert.deepEqual(noteErrors, []);
    await notes.goto(pathToFileURL(path.join(root, 'LEARNING_RESOURCES.html')).href);
    await notes.screenshot({ path: path.join(root, `research/${prefix}-notes-320.png`) });
    report.notes_navigation = 'guide → preparation → worksheet block 2 → guide';
    report.notes_narrow_layout = { pages: noteSources.length, keyboard_scrolled_tables: scrollableTables, errors: noteErrors };
    await notes.close();
    const fallback = await browser.newPage({ javaScriptEnabled: false });
    await fallback.context().setOffline(true);
    await fallback.goto(url);
    for (const selector of ['details.catalog', 'details.task-route']) {
      const groups = fallback.locator(selector);
      for (let i = 0; i < await groups.count(); i++) await groups.nth(i).locator(':scope > summary').click();
    }
    assert.equal(await visibleTools(fallback).count(), 200);
    assert.equal(await fallback.locator('ol.steps:visible').count(), 33);
    report.no_javascript_browsing = 'pass';
    await fallback.emulateMedia({ media: 'print' });
    assert.equal(await fallback.locator('nav').isVisible(), false);
    report.print_navigation_hidden = true;
    assert.equal(htmlHash(), report.html_sha256, 'HTML changed while tests ran; rerun against stable file');
    assert.deepEqual(noteHashes(), report.notes_sha256, 'Notes changed during browser checks');
    fs.writeFileSync(path.join(root, `research/${prefix}-browser.json`), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
