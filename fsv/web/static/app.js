/* FSV dashboard client — liquid glass */
const $ = (id) => document.getElementById(id);
const api = (p, o) => fetch(p, o).then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)).catch(()=>Promise.reject({detail:r.statusText})));

let currentScanId = null;
let ws = null;
let allFindings = [];
let activeSev = null;        // severity filter
let searchTerm = "";

const SEV = ["critical","high","medium","low","info"];
const SEV_COLOR = { critical:"var(--crit)", high:"var(--high)", medium:"var(--med)", low:"var(--low)", info:"var(--info)" };
const GRADE_COLOR = { "A+":"var(--low)","A":"var(--low)","B":"var(--med)","C":"var(--high)","D":"var(--high)","F":"var(--crit)" };

/* ── theme ── */
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  try{ localStorage.setItem("fsv-theme", t); }catch(e){}
}
$("themeBtn").onclick = () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
(function(){ let t="dark"; try{ t = localStorage.getItem("fsv-theme") || "dark"; }catch(e){} applyTheme(t); })();

api("/api/info").then(d => { $("ver").textContent = d.version; }).catch(()=>{});

function esc(s){ return (s||"").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function normTarget(raw){ raw=raw.trim(); if(!raw) return ""; if(!/^https?:\/\//i.test(raw)) raw="https://"+raw; return raw; }

/* ── animation helpers ── */
function animateCount(el, to, dur=900){
  const from = parseInt(el.textContent) || 0;
  if(from === to){ el.textContent = to; return; }
  const t0 = performance.now();
  const ease = t => 1 - Math.pow(1 - t, 3);
  function tick(now){
    const p = Math.min(1, (now - t0) / dur);
    el.textContent = Math.round(from + (to - from) * ease(p));
    if(p < 1) requestAnimationFrame(tick);
    else { el.textContent = to; el.classList.add("bump"); setTimeout(()=>el.classList.remove("bump"),400); }
  }
  requestAnimationFrame(tick);
}

var _toastN = 0;
function toast(title, sub, color="var(--low)"){
  let host = $("toasts");
  if(!host){ host = document.createElement("div"); host.id="toasts"; document.body.appendChild(host); }
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<span class="tdot" style="background:${color};box-shadow:0 0 8px ${color}"></span>
    <div><b>${esc(title)}</b>${sub?`<div class="tsub">${esc(sub)}</div>`:""}</div>`;
  host.appendChild(el);
  const id = ++_toastN;
  setTimeout(()=>{ el.classList.add("out"); setTimeout(()=>el.remove(),400); }, 4200);
  return id;
}

/* ── run scan ── */
$("scanBtn").onclick = startScan;
$("cancelBtn").onclick = cancelScan;
$("target").addEventListener("keydown", e => { if(e.key==="Enter") startScan(); });

async function startScan(){
  const target = normTarget($("target").value);
  if(!target){ $("target").focus(); return; }
  if(!$("authorized").checked){ flashAuth(); return; }

  $("scanBtn").disabled = true;
  $("scanBtn").classList.add("loading");
  $("scanBtn").querySelector("span").textContent = "Scanning";
  $("cancelBtn").classList.remove("hidden");
  $("progressCard").classList.add("show");
  $("overview").classList.remove("show");
  $("resultsSection").classList.add("hidden");
  $("emptyState").classList.remove("show");
  $("findings").innerHTML = ""; allFindings = []; activeSev = null; searchTerm = "";
  setProgress("init", 0, "Starting scan…");
  toast("Scan started", normTarget($("target").value).replace(/^https?:\/\//,""), "var(--low)");

  let res;
  try{
    res = await api("/api/scan", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({
        target, crawl:$("crawl").checked, profile:$("profile").value,
        max_urls:parseInt($("maxUrls").value), depth:parseInt($("depth").value),
        threads:parseInt($("threads").value), timeout:parseInt($("timeout").value),
        authorized:true,
      })
    });
  }catch(err){ setProgress("error",0,err.detail||"Failed to start scan"); resetBtn(); return; }

  currentScanId = res.scan_id;
  openWs(currentScanId);
}

async function cancelScan(){
  if(!currentScanId) return;
  $("cancelBtn").textContent = "Stopping…";
  try{ await api(`/api/scan/${currentScanId}/cancel`, {method:"POST"}); }catch(e){}
}

function openWs(scanId){
  const proto = location.protocol==="https:"?"wss":"ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);
  ws.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    if(d.type==="progress") setProgress(d.phase, d.pct, d.message);
    else if(d.type==="complete") finishScan(scanId);
  };
  ws.onerror = () => pollUntilDone(scanId);
}
async function pollUntilDone(scanId){
  for(let i=0;i<900;i++){
    try{ const d=await api(`/api/scan/${scanId}`);
      if(["completed","failed","cancelled"].includes(d.status)){ finishScan(scanId); return; } }catch(e){}
    await new Promise(r=>setTimeout(r,1000));
  }
}

function setProgress(phase,pct,msg){
  $("pPhase").textContent = phase;
  $("pPct").textContent = Math.round(pct)+"%";
  $("pFill").style.width = pct+"%";
  $("pMsg").textContent = msg||"";
}

async function finishScan(scanId){
  setProgress("done",100,"Scan complete");
  let d;
  try{ d = await api(`/api/scan/${scanId}`); renderResult(d); }catch(e){}
  resetBtn(); loadHistory();
  setTimeout(()=>$("progressCard").classList.remove("show"),1100);
  if(ws){ ws.close(); ws=null; }
  if(d){
    const c=d.counts||{};
    if(d.status==="cancelled") toast("Scan cancelled","Partial results shown","var(--med)");
    else if(d.status==="failed") toast("Scan failed", d.error||"", "var(--crit)");
    else if((c.critical||0)+(c.high||0)>0)
      toast(`Grade ${d.grade} · ${c.total} findings`, `${c.critical} critical, ${c.high} high`, "var(--crit)");
    else
      toast(`Grade ${d.grade} · scan complete`, `${c.total} findings`, "var(--low)");
  }
}
function resetBtn(){
  $("scanBtn").disabled=false;
  $("scanBtn").classList.remove("loading");
  $("scanBtn").querySelector("span").textContent="Run Scan";
  $("cancelBtn").classList.add("hidden");
  $("cancelBtn").textContent="Stop";
}
function flashAuth(){
  const b=document.querySelector(".auth-box");
  b.style.borderColor="var(--crit)";
  b.animate([{transform:"translateX(0)"},{transform:"translateX(-6px)"},{transform:"translateX(6px)"},{transform:"translateX(0)"}],{duration:300});
  setTimeout(()=>b.style.borderColor="",1200);
}

/* ── render ── */
function renderResult(d){
  const c = d.counts||{};
  $("overview").classList.add("show");
  animateCount($("cCrit"), c.critical||0); animateCount($("cHigh"), c.high||0);
  animateCount($("cMed"), c.medium||0); animateCount($("cLow"), c.low||0); animateCount($("cInfo"), c.info||0);

  // gauge — animate ring from empty
  const score=d.risk_score||0, grade=d.grade||"—";
  const gc = GRADE_COLOR[grade]||"var(--info)";
  const circ=327, off=circ-(circ*Math.min(score,100)/100);
  $("gFill").style.strokeDashoffset=circ;
  requestAnimationFrame(()=>requestAnimationFrame(()=>{ $("gFill").style.strokeDashoffset=off; }));
  $("gFill").style.stroke=gc;
  $("grade").textContent=grade; $("grade").style.color=gc;
  animateCount($("riskScore"), score);
  $("ovTarget").textContent=(d.target||"").replace(/^https?:\/\//,"");
  $("ovTech").innerHTML=(d.tech_stack||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join("");

  $("dlMd").href=`/api/scan/${d.scan_id}/report.md`;
  $("dlJson").href=`/api/scan/${d.scan_id}/report.json`;

  allFindings = d.findings||[];
  if(allFindings.length===0){
    $("resultsSection").classList.add("hidden");
    $("emptyState").classList.add("show");
    $("emptyState").querySelector(".big").textContent =
      d.status==="failed" ? "Scan failed" : d.status==="cancelled" ? "Scan cancelled" : "No vulnerabilities found";
    $("emptyState").querySelector(".small").textContent = d.error || "The target passed all enabled checks.";
    return;
  }
  $("emptyState").classList.remove("show");
  $("resultsSection").classList.remove("hidden");
  renderFilterChips();
  renderFindings();
}

function renderFilterChips(){
  const counts={}; SEV.forEach(s=>counts[s]=0);
  allFindings.forEach(f=>counts[f.severity]++);
  let ci=0;
  const chips=[`<span class="fchip ${activeSev===null?'active':''}" data-sev="" style="--i:${ci++}">all · ${allFindings.length}</span>`];
  SEV.forEach(s=>{ if(counts[s]>0) chips.push(
    `<span class="fchip ${activeSev===s?'active':''}" data-sev="${s}" style="--i:${ci++};${activeSev===s?'':'color:'+SEV_COLOR[s]}">${s} · ${counts[s]}</span>`);});
  $("filterRow").innerHTML=chips.join("");
  $("filterRow").querySelectorAll(".fchip").forEach(ch=>ch.onclick=()=>{
    activeSev = ch.dataset.sev || null; renderFilterChips(); renderFindings();
  });
}

function renderFindings(){
  let list = allFindings;
  if(activeSev) list = list.filter(f=>f.severity===activeSev);
  if(searchTerm){
    const q=searchTerm.toLowerCase();
    list = list.filter(f=>(f.title+f.description+f.url+(f.module||"")+(f.cwe||"")).toLowerCase().includes(q));
  }
  $("fCount").textContent = list.length===allFindings.length ? allFindings.length : `${list.length}/${allFindings.length}`;
  $("findings").innerHTML = list.map((f,i)=>renderFinding(f,i)).join("") ||
    `<div class="empty show" style="padding:40px"><div class="small">No findings match this filter.</div></div>`;
  $("findings").querySelectorAll(".f-head").forEach(h=>h.onclick=()=>h.closest(".finding").classList.toggle("open"));
}

function renderFinding(f, i=0){
  const refs=(f.references||[]).map(r=>`<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join("<br>");
  const tags=[]; if(f.module)tags.push(f.module); if(f.cwe)tags.push(f.cwe);
  if(f.cvss_score!=null)tags.push("CVSS "+f.cvss_score); if(f.parameter)tags.push("param: "+f.parameter);
  const conf = f.confidence ? `<span class="tag conf-${f.confidence}">${f.confidence}</span>` : "";
  return `<div class="glass finding" style="--i:${Math.min(i,24)}">
    <div class="f-head">
      <span class="sev ${f.severity}">${f.severity}</span>
      <span class="f-title">${esc(f.title)}</span>
      <span class="f-meta">${esc((f.url||"").replace(/^https?:\/\//,""))}</span>
      <span class="f-arrow">›</span>
    </div>
    <div class="f-body"><div class="f-inner">
      <div class="tags">${conf}${tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div>
      <h4>Description</h4><p>${esc(f.description)}</p>
      ${f.evidence?`<h4>Evidence</h4><pre>${esc(f.evidence)}</pre>`:""}
      ${f.recommendation?`<h4>Remediation</h4><p>${esc(f.recommendation)}</p>`:""}
      ${refs?`<h4>References</h4><p>${refs}</p>`:""}
    </div></div></div>`;
}

/* stat cards act as severity filters */
document.querySelectorAll(".stat").forEach(s=>s.onclick=()=>{
  const sev=s.dataset.sev;
  activeSev = (activeSev===sev)?null:sev;
  document.querySelectorAll(".stat").forEach(x=>x.classList.toggle("active", x.dataset.sev===activeSev));
  if(allFindings.length){ renderFilterChips(); renderFindings();
    document.querySelector(".sect-title").scrollIntoView({behavior:"smooth",block:"start"}); }
});

/* search */
$("search").addEventListener("input", e=>{ searchTerm=e.target.value; renderFindings(); });

/* ── history ── */
$("refreshHist").onclick = loadHistory;
async function loadHistory(){
  let scans; try{ scans=await api("/api/scans?limit=15"); }catch(e){ return; }
  $("histList").innerHTML = scans.map((s,i)=>{
    const c=s.counts||{};
    const dots=SEV.filter(k=>c[k]>0).map(k=>`<span class="dot" style="color:${SEV_COLOR[k]}">${c[k]}</span>`).join("");
    const when=s.started_at?new Date(s.started_at).toLocaleString():"";
    const g=s.grade||"—", gc=GRADE_COLOR[g]||"var(--info)";
    return `<div class="glass hist-item" data-id="${s.scan_id}" style="--i:${Math.min(i,20)}">
      <span class="hist-grade" style="color:${gc}">${g}</span>
      <span class="ht">${esc(s.target)}</span>
      <span class="hc">${dots||'<span class="dot" style="color:var(--low)">clean</span>'}</span>
      <span class="hist-time">${esc(when)}</span></div>`;
  }).join("") || `<div class="empty show" style="padding:30px"><div class="small">No scans yet.</div></div>`;
  $("histList").querySelectorAll(".hist-item").forEach(el=>el.onclick=async()=>{
    try{ renderResult(await api(`/api/scan/${el.dataset.id}`)); window.scrollTo({top:0,behavior:"smooth"}); }catch(e){}
  });
}
loadHistory();
