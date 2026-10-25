// Regenerates the dashboard screenshots used in the README.
//
//   python examples/demo_site.py &                       # the demo target
//   FSV_DB=/tmp/readme.db fsv scan http://127.0.0.1:8961 --authorize --quiet
//   FSV_DB=/tmp/readme.db FSV_PORT=7795 fsv-web &        # dashboard
//   node scripts/screenshots.cjs                         # needs Playwright (npm i -D playwright)
//
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const OUT = process.env.OUT || ".";
const URL = process.env.FSV_URL || 'http://127.0.0.1:7795/';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 1.5 });
  await page.goto(URL, { waitUntil: 'networkidle' });
  await page.waitForSelector('.hist-item');
  await page.click('.hist-item .ht');                       // open the latest scan from history
  await page.waitForSelector('#overview.show');
  await page.waitForTimeout(2200);                          // let the count-up and gauge animations finish
  await page.addStyleTag({ content: '*{scroll-behavior:auto!important}' });
  // show the form as if it had just been used
  await page.fill('#target', 'http://127.0.0.1:8961');
  await page.check('#authorized', { force: true });
  // the ambient background is position:fixed — make the viewport as tall as the page so a full-page
  // capture has no seam where the fixed layer ends
  const fit = async () => page.setViewportSize({ width: 1180,
    height: await page.evaluate(() => Math.ceil(document.documentElement.scrollHeight)) });
  await fit();

  // A) header → scan panel → gauge/stats → attack paths
  const bottom = await page.$eval('#pathsCard', e => e.getBoundingClientRect().bottom + window.scrollY);
  await page.screenshot({ path: `${OUT}/dashboard.png`, fullPage: true,
                          clip: { x: 0, y: 0, width: 1180, height: Math.ceil(bottom + 24) } });

  // B) findings with one expanded (shows masked evidence)
  await page.click('.finding .f-head');
  await page.waitForTimeout(500);
  await fit();
  const top = await page.$eval('#owaspCard', e => e.getBoundingClientRect().top + window.scrollY);
  const end = await page.$$eval('.finding', els => els[Math.min(7, els.length - 1)].getBoundingClientRect().bottom + window.scrollY);
  await page.screenshot({ path: `${OUT}/findings.png`, fullPage: true,
                          clip: { x: 0, y: Math.floor(top - 12), width: 1180, height: Math.ceil(end - top + 36) } });
  await browser.close();
})();
