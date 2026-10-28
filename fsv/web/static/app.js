/* FSV dashboard client — liquid glass */
const $ = (id) => document.getElementById(id);
/* API token (only needed when the server runs with FSV_TOKEN). Taken once from
   ?token=… in the URL, then remembered in this browser. */
let TOKEN = "";
try {
  const q = new URLSearchParams(location.search).get("token");
  if (q) { localStorage.setItem("fsv-token", q); history.replaceState(null, "", location.pathname); }
  TOKEN = localStorage.getItem("fsv-token") || "";
} catch (e) {}
const withToken = (u) => TOKEN ? u + (u.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN) : u;

async function api(p, o = {}) {
  const opts = { ...o, headers: { ...(o.headers || {}), ...(TOKEN ? { "X-FSV-Token": TOKEN } : {}) } };
  const r = await fetch(p, opts);
  if (r.status === 401) {
    const t = prompt("This FSV server requires an API token (FSV_TOKEN):", "");
    if (t) { TOKEN = t.trim(); try { localStorage.setItem("fsv-token", TOKEN); } catch (e) {} return api(p, o); }
  }
  if (r.ok) return r.json();
  let err; try { err = await r.json(); } catch (e) { err = { detail: r.statusText }; }
  throw err;
}

let currentScanId = null;
let currentResult = null;
let ws = null;
let allFindings = [];
let activeSev = null;
let searchTerm = "";
let MODULES = [];
let compareSel = [];
let sortBy = "severity";
let modFilter = "";
let selected = new Set();          // fingerprints ticked for bulk triage
let lastFocus = null;              // element to give focus back to when a dialog closes

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--info)" };
const GRADE_COLOR = { "A+": "var(--low)", "A": "var(--low)", "B": "var(--med)", "C": "var(--high)", "D": "var(--high)", "F": "var(--crit)" };
const STATUS_LABELS = {
  open: "Open", confirmed: "Confirmed", false_positive: "False positive",
  accepted_risk: "Accepted risk", fixed: "Fixed", superseded: "Chain broken",
};

/* ── theme ── */
function applyTheme(t) {
  const root = document.documentElement;
  if (root.dataset.theme && root.dataset.theme !== t) {          // not on first paint
    root.classList.add("theming"); clearTimeout(applyTheme._t);
    applyTheme._t = setTimeout(() => root.classList.remove("theming"), 600);
  }
  root.dataset.theme = t;
  try { localStorage.setItem("fsv-theme", t); } catch (e) {}
}
$("themeBtn").onclick = () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
(function () { let t = "dark"; try { t = localStorage.getItem("fsv-theme") || "dark"; } catch (e) {} applyTheme(t); })();

const plural = (n, word) => `${n || 0} ${word}${(n || 0) === 1 ? "" : "s"}`;
function statsPill(o) {
  return `<span>${plural(o.scans, "scan")}</span><span>${plural(o.targets, "target")}</span>` +
    (o.triaged ? `<span>${o.triaged} triaged</span>` : "");
}

function esc(s) { return (s || "").toString().replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function normTarget(raw) { raw = raw.trim(); if (!raw) return ""; if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw; return raw; }
function hostOf(u) { try { return new URL(normTarget(u)).host; } catch (e) { return u; } }

/* ── info / modules / global stats ── */
api("/api/info").then(d => {
  $("ver").textContent = d.version;
  MODULES = d.modules || [];
  buildModuleGrid();
  const o = d.overview || {};
  $("globalStats").innerHTML = statsPill(o);
}).catch(() => {});

function buildModuleGrid() {
  const grid = $("modGrid");
  grid.innerHTML = MODULES.map(m => `
    <label class="mod ${m.category}" title="${esc(m.description)}">
      <input type="checkbox" data-mod="${m.name}" data-cat="${m.category}" checked>
      <span class="mod-name">${esc(m.name)}${m.external ? ' <i class="ext" title="contacts hosts other than the target">↗</i>' : ""}</span>
      <span class="mod-cat">${m.category === "active" ? "active" : "passive"}</span>
    </label>`).join("");
  grid.querySelectorAll("input").forEach(i => i.onchange = updateModCount);
  updateModCount();
}
function selectedModules() {
  return [...$("modGrid").querySelectorAll("input:checked")].map(i => i.dataset.mod);
}
function updateModCount() {
  const n = selectedModules().length;
  $("modCount").textContent = `(${n}/${MODULES.length} selected)`;
}
document.querySelectorAll(".chip-btn").forEach(b => b.onclick = () => {
  const mode = b.dataset.mod;
  $("modGrid").querySelectorAll("input").forEach(i => {
    i.checked = mode === "all" ? true : mode === "none" ? false : i.dataset.cat === "passive";
  });
  updateModCount();
});
$("advToggle").onclick = () => {
  const p = $("advPanel"); p.classList.toggle("open");
  $("advToggle").classList.toggle("on", p.classList.contains("open"));
};

/* reflect http/https prefix as the user types a scheme */
$("target").addEventListener("input", () => {
  $("target").parentElement.classList.toggle("has-scheme", /^https?:\/\//i.test($("target").value.trim()));
});

/* ── animation helpers ── */
function animateCount(el, to, dur = 900) {
  const from = parseInt(el.textContent) || 0;
  if (from === to) { el.textContent = to; return; }
  const t0 = performance.now();
  const ease = t => 1 - Math.pow(1 - t, 3);
  (function tick(now) {
    const p = Math.min(1, (now - t0) / dur);
    el.textContent = Math.round(from + (to - from) * ease(p));
    if (p < 1) requestAnimationFrame(tick);
    else { el.textContent = to; el.classList.add("bump"); setTimeout(() => el.classList.remove("bump"), 400); }
  })(performance.now());
}

var _toastN = 0;
function toast(title, sub, color = "var(--low)") {
  let host = $("toasts");
  if (!host) { host = document.createElement("div"); host.id = "toasts"; document.body.appendChild(host); }
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<span class="tdot" style="background:${color};box-shadow:0 0 8px ${color}"></span>
    <div><b>${esc(title)}</b>${sub ? `<div class="tsub">${esc(sub)}</div>` : ""}</div>`;
  host.appendChild(el);
  setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 400); }, 4200);
  return ++_toastN;
}

/* ── run scan ── */
$("scanBtn").onclick = startScan;
$("cancelBtn").onclick = cancelScan;
$("target").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });

async function startScan() {
  const target = normTarget($("target").value);
  if (!target) { $("target").focus(); return; }
  if (!$("authorized").checked) { flashAuth(); return; }

  const mods = selectedModules();
  if (mods.length === 0) { toast("No modules selected", "Pick at least one module", "var(--med)"); return; }

  $("scanBtn").disabled = true;
  $("scanBtn").classList.add("loading");
  $("scanBtn").querySelector("span").textContent = "Scanning";
  $("cancelBtn").classList.remove("hidden");
  $("progressCard").classList.add("show");
  $("overview").classList.remove("show");
  $("owaspCard").classList.remove("show");
  $("pathsCard").classList.remove("show"); $("warnBar").classList.remove("show");
  $("resultsSection").classList.add("hidden");
  $("emptyState").classList.remove("show");
  $("findings").innerHTML = ""; allFindings = []; activeSev = null; searchTerm = "";
  $("search").value = "";
  setProgress("init", 0, "Starting scan…", 0);
  toast("Scan started", hostOf(target), "var(--low)");

  const body = {
    target, crawl: $("crawl").checked, profile: $("profile").value,
    max_urls: parseInt($("maxUrls").value), depth: parseInt($("depth").value),
    threads: parseInt($("threads").value), timeout: parseInt($("timeout").value),
    rate_per_sec: parseFloat($("rate").value),
    exclude_paths: $("exclude").value.split(",").map(s => s.trim()).filter(Boolean),
    tags: $("tags").value.split(",").map(s => s.trim()).filter(Boolean),
    respect_robots: $("robots").checked,
    max_duration: parseInt($("maxDuration").value),
    use_ct_logs: $("ctlogs").checked,
    allow_external: $("external").checked,
    headers: parseLines($("hdrs").value, ":"),
    cookies: parseLines($("cookies").value, "="),
    authorized: true,
  };
  // only send module list if the user narrowed it
  if (mods.length !== MODULES.length) body.modules = mods;

  let res;
  try {
    res = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch (err) { setProgress("error", 0, err.detail || "Failed to start scan", 0); resetBtn(); toast("Could not start", err.detail || "", "var(--crit)"); return; }

  currentScanId = res.scan_id;
  openWs(currentScanId);
}

function parseLines(text, sep) {
  const out = {};
  text.split("\n").forEach(line => {
    const i = line.indexOf(sep);
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return out;
}

async function cancelScan() {
  if (!currentScanId) return;
  $("cancelBtn").textContent = "Stopping…";
  try { await api(`/api/scan/${currentScanId}/cancel`, { method: "POST" }); } catch (e) {}
}

function openWs(scanId) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(withToken(`${proto}://${location.host}/ws/${scanId}`));
  ws.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    if (d.type === "progress") setProgress(d.phase, d.pct, d.message, d.findings);
    else if (d.type === "complete") {
      if (d.summary === null) {           // dropped from the queue / failed before starting
        setProgress(d.status || "cancelled", 0, d.error || "Scan did not start", 0);
        toast(d.status === "failed" ? "Scan failed" : "Scan cancelled", d.error || "Removed from the queue", "var(--med)");
        resetBtn(); if (ws) { ws.close(); ws = null; }
        setTimeout(() => $("progressCard").classList.remove("show"), 1500);
      } else finishScan(scanId);
    }
  };
  ws.onerror = () => pollUntilDone(scanId);
  ws.onclose = (e) => {
    if (e.code === 4401) { toast("Unauthorized", "API token required", "var(--crit)"); resetBtn(); }
    else if (e.code === 1006 && $("cancelBtn").offsetParent !== null) pollUntilDone(scanId);
  };
}
async function pollUntilDone(scanId) {
  for (let i = 0; i < 1200; i++) {
    try { const d = await api(`/api/scan/${scanId}`); if (["completed", "failed", "cancelled"].includes(d.status)) { finishScan(scanId); return; } } catch (e) {}
    await new Promise(r => setTimeout(r, 1000));
  }
}

const STEPS = ["crawl", "recon", "scan", "done"];
function setProgress(phase, pct, msg, found) {
  $("pPhaseTxt").textContent = phase;
  $("pBar").setAttribute("aria-valuenow", Math.round(pct));
  const at = phase === "done" ? 3 : STEPS.indexOf(phase);
  $("stepTrack").querySelectorAll("li").forEach((li, i) => {
    li.classList.toggle("on", at === i && phase !== "done");
    li.classList.toggle("ok", at > i || (phase === "done"));
  });
  $("progressCard").dataset.phase = phase;
  $("pPct").textContent = Math.round(pct) + "%";
  $("pFill").style.width = pct + "%";
  $("pMsg").textContent = msg || "";
  $("pFound").textContent = found ? `${found} finding${found > 1 ? "s" : ""}` : "";
}

const _finished = new Set();
async function finishScan(scanId) {
  // the WebSocket "complete" message, its close event and the polling fallback can all arrive for one scan
  if (_finished.has(scanId)) return;
  _finished.add(scanId);
  setProgress("done", 100, "Scan complete", undefined);
  let d;
  try { d = await api(`/api/scan/${scanId}`); currentResult = d; renderResult(d); } catch (e) {}
  resetBtn(); loadHistory(); refreshGlobalStats();
  setTimeout(() => $("progressCard").classList.remove("show"), 1100);
  if (ws) { ws.close(); ws = null; }
  if (d) {
    const c = d.counts || {};
    if (d.status === "cancelled") toast("Scan cancelled", "Partial results shown", "var(--med)");
    else if (d.status === "failed") toast("Scan failed", d.error || "", "var(--crit)");
    else if ((c.critical || 0) + (c.high || 0) > 0)
      toast(`Grade ${d.grade} · ${c.total} findings`, `${c.critical} critical, ${c.high} high`, "var(--crit)");
    else
      toast(`Grade ${d.grade} · scan complete`, `${c.total} findings`, "var(--low)");
  }
}
function resetBtn() {
  $("scanBtn").disabled = false;
  $("scanBtn").classList.remove("loading");
  $("scanBtn").querySelector("span").textContent = "Run Scan";
  $("cancelBtn").classList.add("hidden");
  $("cancelBtn").textContent = "Stop";
}
function flashAuth() {
  const b = document.querySelector(".auth-box");
  b.style.borderColor = "var(--crit)";
  b.animate([{ transform: "translateX(0)" }, { transform: "translateX(-6px)" }, { transform: "translateX(6px)" }, { transform: "translateX(0)" }], { duration: 300 });
  setTimeout(() => b.style.borderColor = "", 1200);
  toast("Authorization required", "Tick the box to confirm you may test this target", "var(--med)");
}
function refreshGlobalStats() {
  api("/api/info").then(d => {
    const o = d.overview || {};
    $("globalStats").innerHTML = statsPill(o);
  }).catch(() => {});
}

/* ── render result ── */
function renderResult(d) {
  currentResult = d;
  currentScanId = d.scan_id;
  const c = d.counts || {};
  $("overview").classList.add("show");
  animateCount($("cCrit"), c.critical || 0); animateCount($("cHigh"), c.high || 0);
  animateCount($("cMed"), c.medium || 0); animateCount($("cLow"), c.low || 0); animateCount($("cInfo"), c.info || 0);
  const tot = Math.max(1, c.total || 0);
  document.querySelectorAll(".stat").forEach(st => {
    const bar = st.querySelector(".share i"); if (!bar) return;
    bar.style.width = "0%";
    const k = { crit: "critical", high: "high", med: "medium", low: "low", info: "info" }[st.className.split(" ").find(x => ["crit", "high", "med", "low", "info"].includes(x))];
    requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = Math.round(((c[k] || 0) / tot) * 100) + "%"; }));
  });

  const score = d.risk_score || 0, grade = d.grade || "—";
  const gc = GRADE_COLOR[grade] || "var(--info)";
  const circ = 327, off = circ - (circ * Math.min(score, 100) / 100);
  $("gFill").style.strokeDashoffset = circ;
  requestAnimationFrame(() => requestAnimationFrame(() => { $("gFill").style.strokeDashoffset = off; }));
  $("gFill").style.stroke = gc;
  $("grade").textContent = grade; $("grade").style.color = gc;
  $("grade").classList.remove("pop"); void $("grade").offsetWidth; $("grade").classList.add("pop");
  $("gauge").style.setProperty("--gc", gc);
  animateCount($("riskScore"), score);
  $("ovTarget").textContent = (d.target || "").replace(/^https?:\/\//, "");
  $("ovTech").innerHTML = (d.tech_stack || []).map(t => `<span class="tag">${esc(t)}</span>`).join("");

  renderWarnings(d);
  renderPaths((d.findings || []).filter(f => f.module === "correlation" && (f.status === "open" || f.status === "confirmed")));
  renderOwasp(d.owasp || {}, c.total || 0);
  loadSparkline(d.target);
  loadDelta(d.scan_id);

  updateDownloadLink();
  $("dlFmt").onchange = updateDownloadLink;

  selected.clear(); updateBulkBar();
  allFindings = (d.findings || []).filter(f => f.status === "open" || f.status === "confirmed");
  const suppressed = (d.findings || []).filter(f => !(f.status === "open" || f.status === "confirmed"));
  window._suppressed = suppressed;

  if (allFindings.length === 0 && suppressed.length === 0) {
    $("resultsSection").classList.add("hidden");
    $("emptyState").classList.add("show");
    $("emptyState").querySelector(".big").textContent =
      d.status === "failed" ? "Scan failed" : d.status === "cancelled" ? "Scan cancelled" : "No vulnerabilities found";
    $("emptyState").querySelector(".small").textContent = d.error || "The target passed all enabled checks.";
    return;
  }
  $("emptyState").classList.remove("show");
  $("resultsSection").classList.remove("hidden");
  buildModFilter();
  renderFilterChips();
  renderFindings();
}

function buildModFilter() {
  const mods = [...new Set([...allFindings, ...(window._suppressed || [])].map(f => f.module).filter(Boolean))].sort();
  if (modFilter && !mods.includes(modFilter)) modFilter = "";
  $("modFilter").innerHTML = `<option value="">All modules</option>` +
    mods.map(m => `<option value="${esc(m)}"${m === modFilter ? " selected" : ""}>${esc(m)}</option>`).join("");
}

function updateDownloadLink() {
  if (!currentScanId) return;
  const fmt = $("dlFmt").value;
  const a = $("dlBtn");
  a.href = withToken(`/api/scan/${currentScanId}/report?format=${fmt}`);
  a.textContent = fmt.startsWith("fix-") ? `↓ ${fmt.slice(4)} fixes` : `↓ ${fmt.toUpperCase()}`;
  a.download = `fsv-${fmt}.${fmt.startsWith("fix-") ? "md" : fmt}`;
}

/* ── coverage warnings ── */
function renderWarnings(d) {
  const w = [];
  const errs = d.module_errors || {}, samples = d.module_error_samples || {};
  const names = Object.keys(errs);
  if (names.length)
    w.push(`<b>${names.length} module${names.length > 1 ? "s" : ""} had errors</b> — results may be incomplete: ` +
      names.map(n => `<code>${esc(n)}</code>${samples[n] ? ` <span class="muted">(${esc(samples[n].slice(0, 120))})</span>` : ""}`).join(", "));
  if (d.error && d.status !== "failed") w.push(esc(d.error));
  $("warnBar").innerHTML = w.map(x => `<div class="warn">⚠ ${x}</div>`).join("");
  $("warnBar").classList.toggle("show", w.length > 0);
}

/* ── attack paths (correlated findings) ── */
function renderPaths(list) {
  const card = $("pathsCard");
  if (!list.length) { card.classList.remove("show"); return; }
  card.classList.add("show");
  $("pathsSummary").textContent = `${list.length} chain${list.length > 1 ? "s" : ""} of findings that are worse together`;
  $("pathsList").innerHTML = list.map(f => {
    const parts = (f.description || "").split("\n\n");
    const story = parts[0] || "";
    const steps = ((parts.find(p => p.startsWith("How it plays out:")) || "").split("\n").slice(1)).filter(Boolean);
    const links = ((f.extra || {}).links || []).map(l => `<span class="tag">${esc(l.title)}</span>`).join("");
    return `<div class="path">
      <div class="path-head"><span class="sev ${f.severity}">${f.severity}</span><b>${esc(f.title.replace(/^Attack Path:\s*/, ""))}</b>
        <span class="tag conf-${f.confidence}">${f.confidence}</span></div>
      <p>${esc(story)}</p>
      <ol class="steps">${steps.map(x => `<li>${esc(x.replace(/^\d+\.\s*/, ""))}</li>`).join("")}</ol>
      <div class="links">${links}</div>
      <div class="breakit"><b>Break the chain:</b> ${esc(f.recommendation)}</div>
    </div>`;
  }).join("");
}

/* ── OWASP breakdown ── */
const OWASP_NAMES = {
  A01: "Broken Access Control", A02: "Cryptographic Failures", A03: "Injection",
  A04: "Insecure Design", A05: "Security Misconfiguration", A06: "Vulnerable Components",
  A07: "Auth Failures", A08: "Integrity Failures", A09: "Logging Failures", A10: "SSRF",
  other: "Uncategorized",
};
function renderOwasp(breakdown, total) {
  const keys = Object.keys(breakdown);
  if (!keys.length || !total) { $("owaspCard").classList.remove("show"); return; }
  $("owaspCard").classList.add("show");
  const max = Math.max(...Object.values(breakdown));
  $("owaspSummary").textContent = `${keys.length} categor${keys.length > 1 ? "ies" : "y"} across ${total} findings`;
  $("owaspBars").innerHTML = keys.sort().map((k, ki) => {
    const n = breakdown[k], w = Math.round((n / max) * 100);
    return `<div class="owasp-row" style="--w:${w}%;--k:${ki}">
      <span class="owasp-id">${k === "other" ? "—" : k}</span>
      <span class="owasp-name">${esc(OWASP_NAMES[k] || k)}</span>
      <span class="owasp-bar"><span></span></span>
      <span class="owasp-n">${n}</span></div>`;
  }).join("");
}

/* ── change since the previous scan of this host ── */
async function loadDelta(scanId) {
  const el = $("ovDelta"); el.innerHTML = "";
  let d; try { d = await api(`/api/scan/${scanId}/delta`); } catch (e) { return; }
  if (!d || !d.previous || currentScanId !== scanId) return;
  const cls = d.risk_delta > 0 ? "up" : d.risk_delta < 0 ? "down" : "";
  el.innerHTML = `vs previous: <span class="${cls}">${d.risk_delta > 0 ? "+" : ""}${d.risk_delta} risk</span>` +
    ` · <span class="up">${d.counts.new} new</span> · <span class="down">${d.counts.resolved} resolved</span>`;
}

/* ── sparkline trend ── */
async function loadSparkline(target) {
  const el = $("spark"); el.innerHTML = "";
  let pts;
  try { pts = await api(`/api/trend?target=${encodeURIComponent(hostOf(target))}&limit=20`); } catch (e) { return; }
  if (!pts || pts.length < 2) return;
  const scores = pts.map(p => p.risk_score);
  const w = 160, h = 34, max = Math.max(100, ...scores), n = scores.length;
  const path = scores.map((s, i) => `${(i / (n - 1)) * w},${h - (s / max) * h}`).join(" ");
  const last = pts[pts.length - 1], prev = pts[pts.length - 2];
  const dir = last.risk_score < prev.risk_score ? "down" : last.risk_score > prev.risk_score ? "up" : "flat";
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="spk ${dir}">
    <polyline points="${path}" fill="none" stroke-width="2"></polyline></svg>
    <span class="spk-l">${n} scans · trend ${dir === "down" ? "↓ improving" : dir === "up" ? "↑ worse" : "→ flat"}</span>`;
}

/* ── filter chips ── */
function renderFilterChips() {
  const counts = {}; SEV.forEach(s => counts[s] = 0);
  allFindings.forEach(f => counts[f.severity]++);
  let ci = 0;
  const chips = [`<span class="fchip ${activeSev === null ? 'active' : ''}" data-sev="" style="--i:${ci++}">all · ${allFindings.length}</span>`];
  SEV.forEach(s => { if (counts[s] > 0) chips.push(`<span class="fchip ${activeSev === s ? 'active' : ''}" data-sev="${s}" style="--i:${ci++};${activeSev === s ? '' : 'color:' + SEV_COLOR[s]}">${s} · ${counts[s]}</span>`); });
  const sup = (window._suppressed || []).length;
  if (sup) chips.push(`<span class="fchip ${activeSev === '_sup' ? 'active' : ''}" data-sev="_sup" style="--i:${ci++}">triaged · ${sup}</span>`);
  $("filterRow").innerHTML = chips.join("");
  $("filterRow").querySelectorAll(".fchip").forEach(ch => ch.onclick = () => {
    activeSev = ch.dataset.sev || null; renderFilterChips(); renderFindings();
  });
}

function renderFindings() {
  let list = activeSev === "_sup" ? (window._suppressed || []) : allFindings;
  if (activeSev && activeSev !== "_sup") list = list.filter(f => f.severity === activeSev);
  if (modFilter) list = list.filter(f => f.module === modFilter);
  list = sortFindings(list);
  if (searchTerm) {
    const q = searchTerm.toLowerCase();
    list = list.filter(f => (f.title + f.description + f.url + (f.module || "") + (f.cwe || "") + (f.owasp || "")).toLowerCase().includes(q));
  }
  const base = activeSev === "_sup" ? (window._suppressed || []).length : allFindings.length;
  $("fCount").textContent = list.length === base ? base : `${list.length}/${base}`;
  $("findings").innerHTML = list.map((f, i) => renderFinding(f, i)).join("") ||
    `<div class="empty show" style="padding:40px"><div class="small">No findings match this filter.</div></div>`;
  $("findings").querySelectorAll(".f-head").forEach(h => {
    const toggle = () => {
      const f = h.closest(".finding"); f.classList.toggle("open");
      h.setAttribute("aria-expanded", f.classList.contains("open"));
      syncExpandBtn();
    };
    h.onclick = (e) => { if (e.target.closest(".triage,.f-pick")) return; toggle(); };
    h.onkeydown = (e) => {
      if (e.target !== h) return;
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    };
  });
  $("findings").querySelectorAll(".f-pick input").forEach(cb => cb.onchange = () => {
    const fp = cb.dataset.fp;
    cb.checked ? selected.add(fp) : selected.delete(fp);
    cb.closest(".finding").classList.toggle("picked", cb.checked);
    updateBulkBar();
  });
  wireTriage();
  syncExpandBtn();
}

const CONF_RANK = { certain: 3, firm: 2, tentative: 1 };
function sortFindings(list) {
  const sevRank = f => SEV.length - SEV.indexOf(f.severity);
  const cmp = {
    severity: (a, b) => sevRank(b) - sevRank(a) || (CONF_RANK[b.confidence] || 0) - (CONF_RANK[a.confidence] || 0),
    confidence: (a, b) => (CONF_RANK[b.confidence] || 0) - (CONF_RANK[a.confidence] || 0) || sevRank(b) - sevRank(a),
    module: (a, b) => (a.module || "").localeCompare(b.module || "") || sevRank(b) - sevRank(a),
    url: (a, b) => (a.url || "").localeCompare(b.url || "") || sevRank(b) - sevRank(a),
  }[sortBy] || (() => 0);
  return [...list].sort(cmp);          // stable; never mutates allFindings
}
$("sortBy").onchange = (e) => { sortBy = e.target.value; renderFindings(); };
$("modFilter").onchange = (e) => { modFilter = e.target.value; renderFindings(); };

/* expand / collapse every visible finding */
function syncExpandBtn() {
  const all = [...document.querySelectorAll("#findings .finding")];
  const allOpen = all.length > 0 && all.every(f => f.classList.contains("open"));
  $("expandAll").textContent = allOpen ? "⇲ Collapse" : "⇳ Expand";
  $("expandAll").dataset.state = allOpen ? "open" : "closed";
}
function toggleAll() {
  const open = $("expandAll").dataset.state !== "open";
  document.querySelectorAll("#findings .finding").forEach(f => {
    f.classList.toggle("open", open);
    f.querySelector(".f-head").setAttribute("aria-expanded", open);
  });
  syncExpandBtn();
}
$("expandAll").onclick = toggleAll;

/* re-run with whatever the form holds, against the scan that is on screen */
$("rescanBtn").onclick = () => {
  if (!currentResult || $("scanBtn").disabled) return;
  $("target").value = currentResult.target.replace(/^https?:\/\//, "");
  $("target").dispatchEvent(new Event("input"));
  window.scrollTo({ top: 0, behavior: "smooth" });
  startScan();
};

/* ── bulk triage ── */
function updateBulkBar() {
  const n = selected.size;
  $("bulkBar").classList.toggle("hidden", n === 0);
  $("bulkCount").textContent = `${n} selected`;
}
$("bulkClear").onclick = () => {
  selected.clear(); updateBulkBar();
  document.querySelectorAll(".f-pick input").forEach(cb => { cb.checked = false; cb.closest(".finding").classList.remove("picked"); });
};
document.querySelectorAll("[data-bulk]").forEach(b => b.onclick = async () => {
  const status = b.dataset.bulk;
  const ids = allFindings.concat(window._suppressed || []).filter(f => selected.has(f.fingerprint || f.id)).map(f => f.id);
  if (!ids.length) return;
  let note = "";
  if (status === "false_positive" || status === "accepted_risk") {
    note = await askNote(`${ids.length} finding${ids.length > 1 ? "s" : ""} → ${STATUS_LABELS[status]}`);
    if (note === null) return;
  }
  let ok = 0, fail = 0;
  for (const id of ids) {
    try {
      await api(`/api/scan/${currentScanId}/triage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: id, status, note }),
      });
      ok++;
    } catch (e) { fail++; }
  }
  toast(`${ok} triaged as ${STATUS_LABELS[status]}`, fail ? `${fail} failed` : "applies to this host", fail ? "var(--med)" : "var(--low)");
  selected.clear();
  try { renderResult(await api(`/api/scan/${currentScanId}`)); refreshGlobalStats(); } catch (e) {}
});

function renderFinding(f, i = 0) {
  const refs = (f.references || []).map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join("<br>");
  const tags = []; if (f.module) tags.push(f.module);
  if (f.owasp) tags.push(f.owasp); if (f.cwe) tags.push(f.cwe);
  if (f.cvss_score != null) tags.push("CVSS " + f.cvss_score);
  if (f.parameter) tags.push("param: " + f.parameter);
  const conf = (f.module === "correlation" ? '<span class="tag path-tag">attack path</span>' : "") +
    (f.confidence ? `<span class="tag conf-${f.confidence}">${f.confidence}</span>` : "");
  const affected = (f.affected_urls && f.affected_urls.length > 1)
    ? `<h4>Affected URLs (${f.affected_urls.length})</h4><pre>${esc(f.affected_urls.slice(0, 60).join("\n"))}${f.affected_urls.length > 60 ? "\n…" : ""}</pre>` : "";
  const statusBadge = (f.status && f.status !== "open")
    ? `<span class="st-badge ${f.status}">${STATUS_LABELS[f.status] || f.status}</span>` : "";
  return `<div class="glass finding${selected.has(f.fingerprint || f.id) ? " picked" : ""}" data-fp="${esc(f.fingerprint || f.id)}" style="--i:${Math.min(i, 24)}">
    <div class="f-head" role="button" tabindex="0" aria-expanded="false">
      <label class="f-pick" title="Select for bulk triage"><input type="checkbox" data-fp="${esc(f.fingerprint || f.id)}" aria-label="Select ${esc(f.title)}" ${selected.has(f.fingerprint || f.id) ? "checked" : ""}><span class="box"></span></label>
      <span class="sev ${f.severity}">${f.severity}</span>
      <span class="f-title">${esc(f.title)}${statusBadge}</span>
      <span class="f-meta">${esc((f.url || "").replace(/^https?:\/\//, ""))}</span>
      <button type="button" class="triage" data-fp="${esc(f.fingerprint || f.id)}" data-id="${esc(f.id)}" title="Triage" aria-label="Triage: ${esc(f.title)}" aria-haspopup="menu">⋯</button>
      <span class="f-arrow">›</span>
    </div>
    <div class="f-body"><div class="f-inner"><div class="f-pad">
      <div class="tags">${conf}${tags.map(t => `<span class="tag">${esc(t)}</span>`).join("")}</div>
      <h4>Description</h4><p>${esc(f.description)}</p>
      ${f.evidence ? `<h4>Evidence</h4><pre>${esc(f.evidence)}</pre>` : ""}
      ${f.recommendation ? `<h4>Remediation</h4><p>${esc(f.recommendation)}</p>` : ""}
      ${affected}
      ${f.triage_note ? `<h4>Triage note</h4><p>${esc(f.triage_note)}</p>` : ""}
      ${refs ? `<h4>References</h4><p>${refs}</p>` : ""}
    </div></div></div></div>`;
}

/* ── triage ── */
function wireTriage() {
  document.querySelectorAll(".triage").forEach(t => t.onclick = (e) => {
    e.stopPropagation();
    openTriageMenu(t, t.dataset.id);
  });
}
function openTriageMenu(anchor, findingId) {
  document.querySelectorAll(".triage-menu").forEach(m => m.remove());
  const menu = document.createElement("div");
  menu.className = "triage-menu glass"; menu.setAttribute("role", "menu");
  const opts = [["confirmed", "Confirm"], ["false_positive", "False positive"],
                ["accepted_risk", "Accept risk"], ["fixed", "Mark fixed"], ["open", "Reset to open"]];
  menu.innerHTML = opts.map(([v, l]) => `<button role="menuitem" data-st="${v}">${l}</button>`).join("");
  document.body.appendChild(menu);
  const r = anchor.getBoundingClientRect();
  menu.style.top = (r.bottom + window.scrollY + 6) + "px";
  menu.style.left = Math.min(r.left + window.scrollX - 120, window.innerWidth - 180) + "px";
  const items = [...menu.querySelectorAll("button")];
  items[0].focus();
  menu.onkeydown = (e) => {
    const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    else if (e.key === "Escape") { e.preventDefault(); menu.remove(); anchor.focus(); }
    else if (e.key === "Tab") { menu.remove(); }
  };
  items.forEach(b => b.onclick = async () => {
    const status = b.dataset.st;
    let note = "";
    menu.remove();
    if (status === "false_positive" || status === "accepted_risk") {
      note = await askNote(STATUS_LABELS[status]);
      if (note === null) return;
    }
    try {
      await api(`/api/scan/${currentScanId}/triage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: findingId, status, note }),
      });
      toast("Triaged", STATUS_LABELS[status] + " — applies to this host", "var(--low)");
      const fresh = await api(`/api/scan/${currentScanId}`);
      renderResult(fresh); refreshGlobalStats();
    } catch (e) { toast("Triage failed", e.detail || "", "var(--crit)"); }
  });
  setTimeout(() => {
    document.addEventListener("click", function h(ev) {
      if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener("click", h); }
    });
  }, 0);
}

/* stat cards act as severity filters */
document.querySelectorAll(".stat").forEach(s => s.onclick = () => {
  const sev = s.dataset.sev;
  activeSev = (activeSev === sev) ? null : sev;
  document.querySelectorAll(".stat").forEach(x => x.classList.toggle("active", x.dataset.sev === activeSev));
  if (allFindings.length) {
    renderFilterChips(); renderFindings();
    document.querySelector(".sect-title").scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

/* search */
$("search").addEventListener("input", e => { searchTerm = e.target.value; renderFindings(); });

/* ── history + compare ── */
$("refreshHist").onclick = loadHistory;
async function loadHistory() {
  let scans; try { scans = await api("/api/scans?limit=20"); } catch (e) { return; }
  $("histList").innerHTML = scans.map((s, i) => {
    const c = s.counts || {};
    const dots = SEV.filter(k => c[k] > 0).map(k => `<span class="dot" style="color:${SEV_COLOR[k]}">${c[k]}</span>`).join("");
    const when = s.started_at ? new Date(s.started_at).toLocaleString() : "";
    const g = s.grade || "—", gc = GRADE_COLOR[g] || "var(--info)";
    const tags = (s.tags || []).map(t => `<span class="htag">${esc(t)}</span>`).join("");
    const checked = compareSel.includes(s.scan_id) ? "checked" : "";
    return `<div class="glass hist-item ${checked ? 'sel' : ''}" data-id="${s.scan_id}" style="--i:${Math.min(i, 20)}">
      <label class="hist-pick" title="Select to compare"><input type="checkbox" data-id="${s.scan_id}" ${checked}><span class="box"></span></label>
      <span class="hist-grade" style="color:${gc};border-color:${gc}">${g}</span>
      <span class="ht">${esc(s.target)}${s.status === "running" ? '<span class="hist-live">live</span>' : ""}${tags}</span>
      <span class="hc">${dots || '<span class="dot" style="color:var(--low)">clean</span>'}</span>
      <span class="hist-time">${esc(when)}</span>
      <button class="hist-del" data-id="${s.scan_id}" title="Delete scan" aria-label="Delete scan">✕</button></div>`;
  }).join("") || `<div class="empty show" style="padding:30px"><div class="small">No scans yet.</div></div>`;

  $("histList").querySelectorAll(".hist-item").forEach(el => {
    el.onclick = async (e) => {
      if (e.target.closest(".hist-pick")) return;
      if (e.target.closest(".hist-del")) {
        e.stopPropagation();
        if (!confirm("Delete this scan from the local database?")) return;
        try {
          await api(`/api/scan/${el.dataset.id}`, { method: "DELETE" });
          compareSel = compareSel.filter(x => x !== el.dataset.id);
          toast("Scan deleted", "", "var(--info)"); loadHistory(); refreshGlobalStats();
        } catch (err) { toast("Delete failed", err.detail || "", "var(--crit)"); }
        return;
      }
      try { renderResult(await api(`/api/scan/${el.dataset.id}`)); window.scrollTo({ top: 0, behavior: "smooth" }); } catch (e) {}
    };
  });
  $("histList").querySelectorAll(".hist-pick input").forEach(cb => cb.onchange = (e) => {
    const id = cb.dataset.id;
    if (cb.checked) { if (!compareSel.includes(id)) compareSel.push(id); }
    else compareSel = compareSel.filter(x => x !== id);
    if (compareSel.length > 2) { const drop = compareSel.shift(); }
    cb.closest(".hist-item").classList.toggle("sel", cb.checked);
    $("compareBtn").classList.toggle("hidden", compareSel.length !== 2);
    $("histHint").textContent = compareSel.length === 2 ? "ready — click Compare" :
      compareSel.length === 1 ? "select one more" : "select two to compare";
    loadHistory();
  });
}
$("compareBtn").onclick = async () => {
  if (compareSel.length !== 2) return;
  const [a, b] = compareSel;
  let d; try { d = await api(`/api/diff?baseline=${a}&current=${b}`); } catch (e) { toast("Compare failed", e.detail || "", "var(--crit)"); return; }
  showDiff(d);
};
function showDiff(d) {
  const vc = { improved: "var(--low)", regressed: "var(--crit)", unchanged: "var(--med)" }[d.verdict];
  const row = (f) => `<div class="diff-f"><span class="sev ${f.severity}">${f.severity}</span><span>${esc(f.title)}</span></div>`;
  $("diffTitle").innerHTML = `Comparison — <span style="color:${vc}">${d.verdict}</span>`;
  $("diffBody").innerHTML = `
    <div class="diff-head">
      <div><b>${esc(hostOf(d.baseline.target))}</b> · ${d.baseline.started_at.slice(0,10)} → ${d.current.started_at.slice(0,10)}</div>
      <div class="diff-score">risk ${d.baseline.risk_score} → ${d.current.risk_score}
        <span style="color:${vc}">(${d.risk_delta >= 0 ? "+" : ""}${d.risk_delta})</span></div>
    </div>
    <div class="diff-cols">
      <div><h4 style="color:var(--low)">Resolved (${d.counts.resolved})</h4>${d.resolved.map(row).join("") || '<p class="muted">none</p>'}</div>
      <div><h4 style="color:var(--crit)">New (${d.counts.new})</h4>${d.new.map(row).join("") || '<p class="muted">none</p>'}</div>
    </div>
    <p class="muted">${d.counts.persisted} finding(s) persisted across both scans.</p>`;
  openModal($("diffModal"), $("diffClose"));
}
$("diffClose").onclick = () => closeModal($("diffModal"));
$("diffModal").onclick = (e) => { if (e.target === $("diffModal")) closeModal($("diffModal")); };

/* ── dialogs: focus goes in, Escape / backdrop closes, focus returns where it came from ── */
function openModal(el, focusEl) {
  lastFocus = document.activeElement;
  el.classList.add("show");
  setTimeout(() => (focusEl || el.querySelector("button,textarea,input"))?.focus(), 30);
}
function closeModal(el) {
  el.classList.remove("show");
  if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
}
document.addEventListener("keydown", e => {            // keep Tab inside an open dialog
  const open = document.querySelector(".modal-back.show");
  if (!open || e.key !== "Tab") return;
  const f = [...open.querySelectorAll("button,textarea,input,a[href]")].filter(x => !x.disabled && x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});

/* resolves to the note text, or null when cancelled */
function askNote(what) {
  return new Promise(resolve => {
    const m = $("noteModal");
    $("noteHint").textContent = what;
    $("noteText").value = "";
    let done = false;
    const finish = (v) => {
      if (done) return; done = true;
      $("noteForm").onsubmit = $("noteCancel").onclick = m.onclick = null;
      closeModal(m); resolve(v);
    };
    $("noteForm").onsubmit = (e) => { e.preventDefault(); finish($("noteText").value.trim()); };
    $("noteCancel").onclick = () => finish(null);
    m.onclick = (e) => { if (e.target === m) finish(null); };
    m._cancel = () => finish(null);
    openModal(m, $("noteText"));
  });
}

/* keyboard shortcuts */
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    const open = document.querySelector(".modal-back.show");
    if (open) { open._cancel ? open._cancel() : closeModal(open); return; }
  }
  const t = e.target;
  if (t.tagName === "INPUT" || t.tagName === "SELECT" || t.tagName === "TEXTAREA" || t.isContentEditable) {
    if (e.key === "Escape") t.blur();
    return;
  }
  if (e.ctrlKey || e.metaKey || e.altKey) return;      // never hijack browser shortcuts (Ctrl+T, Cmd+/ …)
  if (e.key === "/") { e.preventDefault(); $("search").focus(); }
  else if (e.key.toLowerCase() === "t") applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  else if (e.key.toLowerCase() === "e" && !$("resultsSection").classList.contains("hidden")) toggleAll();
});

loadHistory();

/* re-attach to a scan that was still running when the page was reloaded */
(async function resumeActive() {
  let active; try { active = await api("/api/active"); } catch (e) { return; }
  if (!active || !active.length) return;
  const s = active[active.length - 1];
  currentScanId = s.scan_id;
  $("target").value = s.target;
  $("target").parentElement.classList.toggle("has-scheme", true);
  $("scanBtn").disabled = true; $("scanBtn").classList.add("loading");
  $("scanBtn").querySelector("span").textContent = "Scanning";
  $("cancelBtn").classList.remove("hidden");
  $("progressCard").classList.add("show");
  const l = s.latest;
  if (l && l.type === "progress") setProgress(l.phase, l.pct, l.message, l.findings);
  toast("Re-attached to running scan", hostOf(s.target), "var(--low)");
  openWs(s.scan_id);
})();

/* cursor spotlight on glass cards (CSS reads --mx/--my; one rAF per move, no layout) */
(function () {
  if (matchMedia("(hover:none)").matches || matchMedia("(prefers-reduced-motion:reduce)").matches) return;
  let raf = 0, ev = null;
  document.addEventListener("pointermove", e => {
    ev = e; if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const g = ev.target.closest && ev.target.closest(".glass");
      if (!g) return;
      const r = g.getBoundingClientRect();
      g.style.setProperty("--mx", (ev.clientX - r.left) + "px");
      g.style.setProperty("--my", (ev.clientY - r.top) + "px");
    });
  }, { passive: true });
})();
