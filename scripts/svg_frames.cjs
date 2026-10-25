// Renders frames of the animated SVGs at fixed times so they can be checked by eye / in CI artefacts.
//   node scripts/svg_frames.cjs docs/assets/hero.svg 0.5,2,4  out_prefix
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const path = require('path');
(async () => {
  const [file, times, prefix] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 700 } });
  await page.goto('file://' + path.resolve(file));
  const [w, h] = await page.evaluate(() => { const s = document.documentElement; return [s.viewBox.baseVal.width, s.viewBox.baseVal.height]; });
  await page.setViewportSize({ width: Math.ceil(w), height: Math.ceil(h) });
  for (const t of times.split(',').map(Number)) {
    await page.evaluate((t) => {
      document.getAnimations().forEach(a => { a.pause(); a.currentTime = t * 1000; });   // CSS animations
      const svg = document.documentElement; if (svg.pauseAnimations) { svg.pauseAnimations(); svg.setCurrentTime(t); }  // SMIL
    }, t);
    await page.waitForTimeout(80);
    await page.screenshot({ path: `${prefix}_${String(t).replace('.', '_')}.png` });
  }
  await browser.close();
})();
