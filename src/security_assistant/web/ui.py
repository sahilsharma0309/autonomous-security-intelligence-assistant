"""The dashboard's HTML, CSS and client-side JavaScript.

Served as one self-contained document. **Nothing is loaded from a CDN**, and
that is a deliberate departure from the usual Tailwind + Cytoscape recipe:

* This console is often the thing you reach for when a network is in a bad
  state, or on an isolated segment with no egress. A dashboard that renders
  blank without internet is useless exactly when it is needed.
* A CDN is a supply-chain surface. This page can engage a kill-switch and
  dispatch agent runs; third-party script running in it inherits that.
  Self-contained means the Content-Security-Policy can forbid every external
  origin outright rather than carving out exceptions.

So the styling is hand-written CSS, and the graph is a small force-directed
renderer on a canvas (about a hundred lines) rather than a graph library. The
cost is a less featureful graph than Cytoscape; the benefit is a console with
no external dependencies at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from security_assistant.web.app import DashboardConfig

__all__ = ["render_index"]

_CSS = """
:root{
  --bg:#05070d; --panel:#0a0f1a; --panel2:#0d1524; --line:#152238;
  --fg:#c8d6e8; --dim:#5a7architecture; --dim:#5a7089;
  --cyan:#00f0ff; --magenta:#ff2e88; --lime:#39ff88; --amber:#ffb020; --red:#ff3b5c;
  --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--mono);font-size:13px;
  background-image:repeating-linear-gradient(0deg,rgba(0,240,255,.02) 0 1px,transparent 1px 3px)}
a{color:var(--cyan)}
header{display:flex;align-items:center;gap:16px;padding:10px 18px;
  border-bottom:1px solid var(--line);
  background:linear-gradient(90deg,#070b14,#0a1120);position:sticky;top:0;z-index:20}
.brand{font-weight:700;letter-spacing:.18em;color:var(--cyan);
  text-shadow:0 0 12px rgba(0,240,255,.5)}
.brand em{color:var(--magenta);font-style:normal}
.spacer{flex:1}
.pill{border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:11px;
  color:var(--dim)}
.pill.on{border-color:var(--lime);color:var(--lime);box-shadow:0 0 10px rgba(57,255,136,.25)}
.pill.warn{border-color:var(--amber);color:var(--amber)}
.pill.bad{border-color:var(--red);color:var(--red);box-shadow:0 0 10px rgba(255,59,92,.25)}
nav{display:flex;gap:2px;padding:0 12px;border-bottom:1px solid var(--line);background:#070b14}
nav button{background:transparent;border:0;border-bottom:2px solid transparent;color:var(--dim);
  font-family:var(--mono);font-size:12px;letter-spacing:.1em;padding:10px 16px;cursor:pointer}
nav button:hover{color:var(--fg)}
nav button.active{color:var(--cyan);border-bottom-color:var(--cyan)}
main{padding:16px}
.view{display:none}.view.active{display:block}
.grid{display:grid;gap:14px}
.g2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
.card>h3{margin:0;padding:9px 12px;font-size:11px;letter-spacing:.16em;color:var(--dim);
  border-bottom:1px solid var(--line);background:var(--panel2);text-transform:uppercase}
.card>div{padding:12px}
input,select,textarea{background:#060a12;border:1px solid var(--line);color:var(--fg);
  font-family:var(--mono);font-size:13px;padding:8px 10px;border-radius:4px;width:100%}
input:focus,select:focus{outline:0;border-color:var(--cyan);box-shadow:0 0 0 1px rgba(0,240,255,.3)}
button.act{background:transparent;border:1px solid var(--cyan);color:var(--cyan);
  font-family:var(--mono);
  font-size:12px;letter-spacing:.08em;padding:8px 14px;border-radius:4px;cursor:pointer}
button.act:hover{background:rgba(0,240,255,.1);box-shadow:0 0 12px rgba(0,240,255,.25)}
button.act.danger{border-color:var(--red);color:var(--red)}
button.act.danger:hover{background:rgba(255,59,92,.1)}
button.act:disabled{opacity:.4;cursor:not-allowed}
.row{display:flex;gap:8px;align-items:center}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--dim);font-weight:400;padding:6px 8px;
  border-bottom:1px solid var(--line);
  text-transform:uppercase;letter-spacing:.1em;font-size:10px}
td{padding:6px 8px;border-bottom:1px solid #0e1728}
tr:hover td{background:rgba(0,240,255,.04)}
.kv{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #0e1728}
.kv span:first-child{color:var(--dim)}
pre.term{background:#04070d;border:1px solid var(--line);border-radius:4px;padding:10px;
  height:340px;overflow:auto;margin:0;font-size:12px;line-height:1.55;white-space:pre-wrap}
pre.term .cmd{color:var(--cyan)}
pre.term .err{color:var(--red)}
canvas{display:block;width:100%;background:#04070d;border-radius:4px}
.bar{height:4px;background:#0e1728;border-radius:2px;overflow:hidden}
.bar>i{display:block;height:100%;width:0;
  background:linear-gradient(90deg,var(--cyan),var(--magenta));
  transition:width .3s}
.tag{display:inline-block;border:1px solid var(--line);border-radius:3px;padding:1px 6px;
  font-size:10px;
  color:var(--dim);margin:1px}
.sev-critical{color:var(--red)}.sev-high{color:#ff7043}.sev-medium{color:var(--amber)}
.sev-low{color:var(--dim)}.sev-info{color:var(--dim)}
#gate{position:fixed;inset:0;background:rgba(3,5,10,.97);display:flex;align-items:center;
  justify-content:center;z-index:100}
#gate .box{width:380px;border:1px solid var(--line);background:var(--panel);border-radius:6px;
  padding:22px}
#gate h2{margin:0 0 6px;color:var(--cyan);letter-spacing:.16em;font-size:14px}
#gate p{color:var(--dim);font-size:11px;line-height:1.6;margin:0 0 14px}
.err-text{color:var(--red);font-size:11px;min-height:15px;margin-top:8px}
.muted{color:var(--dim);font-size:11px}
"""

_JS = r"""
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    ...options,
  });
  if (res.status === 401) { showGate(); throw new Error('unauthenticated'); }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) { /* keep status */ }
    throw new Error(detail);
  }
  return res.headers.get('content-type')?.includes('json') ? res.json() : res.text();
}

function showGate(){ $('#gate').style.display = 'flex'; }
function hideGate(){ $('#gate').style.display = 'none'; }

async function login() {
  const token = $('#token').value.trim();
  $('#gate-err').textContent = '';
  try {
    await api('/api/login', {method:'POST', body: JSON.stringify({token})});
    hideGate(); boot();
  } catch (e) { $('#gate-err').textContent = 'Rejected. Check DASHBOARD_SECRET_KEY.'; }
}

/* ---------- tabs ---------- */
function tab(name) {
  document.querySelectorAll('nav button').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.view').forEach(v =>
    v.classList.toggle('active', v.id === 'view-' + name));
  if (name === 'graph') loadGraph();
  if (name === 'assets') loadAssets();
}

/* ---------- force-directed graph on canvas ----------
   A small spring/repulsion simulation. Not a graph library: this console
   must work with no external scripts, so the ~100 lines here replace a CDN
   dependency that would also need a CSP exception. */
const G = {nodes: [], edges: [], sel: null, raf: null};
const TYPE_COLOR = {
  domain:'#00f0ff', ip_address:'#39ff88', email:'#ff2e88', organization:'#ffb020',
  url:'#ff7043', file_hash:'#b388ff', iot_device:'#00e5ff', network_service:'#7c9cbf',
  social_handle:'#ff80ab', phone:'#80d8ff',
};

async function loadGraph() {
  const data = await api('/api/graph');
  const c = $('#gcanvas');
  G.nodes = data.nodes.map((n, i) => ({
    id: n.data.id, label: n.data.label, type: n.data.type,
    x: c.width/2 + Math.cos(i) * (60 + i * 7),
    y: c.height/2 + Math.sin(i) * (60 + i * 7),
    vx: 0, vy: 0,
  }));
  const index = new Map(G.nodes.map(n => [n.id, n]));
  G.edges = data.edges
    .map(e => ({s: index.get(e.data.source), t: index.get(e.data.target), label: e.data.label}))
    .filter(e => e.s && e.t);
  $('#gstats').textContent =
    `${data.stats.entities} entities · ${data.stats.relationships} relationships` +
    (data.truncated ? ' · truncated' : '');
  if (!G.raf) step();
}

function step() {
  const c = $('#gcanvas'), ctx = c.getContext('2d');
  const W = c.width, H = c.height;

  for (const n of G.nodes) {           // repulsion
    for (const m of G.nodes) {
      if (n === m) continue;
      const dx = n.x - m.x, dy = n.y - m.y;
      const d2 = dx*dx + dy*dy + 0.01;
      if (d2 > 90000) continue;
      const f = 900 / d2;
      n.vx += dx * f; n.vy += dy * f;
    }
    n.vx += (W/2 - n.x) * 0.0012;      // gentle centring
    n.vy += (H/2 - n.y) * 0.0012;
  }
  for (const e of G.edges) {           // spring
    const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
    const d = Math.hypot(dx, dy) || 1;
    const f = (d - 110) * 0.006;
    const ux = dx/d*f, uy = dy/d*f;
    e.s.vx += ux; e.s.vy += uy; e.t.vx -= ux; e.t.vy -= uy;
  }
  for (const n of G.nodes) {
    n.vx *= 0.86; n.vy *= 0.86;
    n.x = Math.max(18, Math.min(W-18, n.x + n.vx));
    n.y = Math.max(18, Math.min(H-18, n.y + n.vy));
  }

  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = 'rgba(90,112,137,.35)'; ctx.lineWidth = 1;
  for (const e of G.edges) {
    ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
  }
  for (const n of G.nodes) {
    const col = TYPE_COLOR[n.type] || '#7c9cbf';
    const sel = G.sel === n.id;
    ctx.beginPath(); ctx.arc(n.x, n.y, sel ? 9 : 6, 0, 7);
    ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = sel ? 18 : 8;
    ctx.fill(); ctx.shadowBlur = 0;
    if (sel || G.nodes.length < 45) {
      ctx.fillStyle = '#c8d6e8'; ctx.font = '10px monospace';
      ctx.fillText(n.label.slice(0, 22), n.x + 11, n.y + 3);
    }
  }
  G.raf = requestAnimationFrame(step);
}

async function pickNode(ev) {
  const c = $('#gcanvas'), r = c.getBoundingClientRect();
  const x = (ev.clientX - r.left) * (c.width / r.width);
  const y = (ev.clientY - r.top) * (c.height / r.height);
  let best = null, bd = 400;
  for (const n of G.nodes) {
    const d = (n.x-x)**2 + (n.y-y)**2;
    if (d < bd) { bd = d; best = n; }
  }
  if (!best) return;
  G.sel = best.id;
  try {
    const d = await api('/api/graph/entity/' + encodeURIComponent(best.id));
    $('#inspector').innerHTML =
      `<div class="kv"><span>key</span><span>${esc(d.entity.key)}</span></div>` +
      `<div class="kv"><span>type</span><span>${esc(d.entity.type)}</span></div>` +
      `<div class="kv"><span>value</span><span>${esc(d.entity.value)}</span></div>` +
      `<div class="kv"><span>confidence</span><span>${d.entity.confidence}</span></div>` +
      `<div class="kv"><span>degree</span><span>${d.degree}</span></div>` +
      `<div class="kv"><span>sources</span>` +
      `<span>${d.entity.sources.map(esc).join(', ') || '-'}</span></div>` +
      `<div style="margin-top:8px" class="muted">NEIGHBOURS</div>` +
      d.neighbors.slice(0, 12).map(n => `<div class="tag">${esc(n.key)}</div>`).join('');
  } catch (e) { $('#inspector').innerHTML = `<div class="muted">${esc(e.message)}</div>`; }
}

/* ---------- risk gauge ---------- */
function gauge(score, band) {
  const c = $('#gauge'), ctx = c.getContext('2d');
  const W = c.width, H = c.height, cx = W/2, cy = H*0.82, r = Math.min(W*0.4, H*0.68);
  ctx.clearRect(0,0,W,H);
  ctx.lineWidth = 14; ctx.lineCap = 'round';
  ctx.strokeStyle = '#0e1728';
  ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, 2*Math.PI); ctx.stroke();

  const col = {benign:'#39ff88', low:'#39ff88', suspicious:'#ffb020',
               high:'#ff7043', critical:'#ff3b5c'}[band] || '#5a7089';
  ctx.strokeStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 16;
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, Math.PI + Math.PI * Math.max(0, Math.min(100, score))/100);
  ctx.stroke(); ctx.shadowBlur = 0;

  ctx.fillStyle = col; ctx.font = 'bold 30px monospace'; ctx.textAlign = 'center';
  ctx.fillText(Math.round(score), cx, cy - 8);
  ctx.fillStyle = '#5a7089'; ctx.font = '11px monospace';
  ctx.fillText((band || 'no scan').toUpperCase(), cx, cy + 12);
}

/* ---------- telemetry sparkline ---------- */
const TELEM = [];
function spark(value) {
  if (value != null) TELEM.push(value);
  while (TELEM.length > 120) TELEM.shift();
  const c = $('#spark'), ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  ctx.strokeStyle = '#00f0ff'; ctx.lineWidth = 1.5; ctx.beginPath();
  TELEM.forEach((v, i) => {
    const x = i / Math.max(1, TELEM.length-1) * c.width;
    const y = c.height - (Math.min(100, v)/100) * (c.height - 6) - 3;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}

/* ---------- actions ---------- */
async function runScan() {
  const url = $('#scan-url').value.trim(); if (!url) return;
  $('#scan-btn').disabled = true; $('#scan-bar').style.width = '25%';
  try {
    const r = await api('/api/scan/url', {method:'POST', body: JSON.stringify({url})});
    $('#scan-bar').style.width = '100%';
    gauge(r.risk_score, r.risk_band);
    $('#findings').innerHTML = (r.findings || []).map(f =>
      `<tr><td class="sev-${esc(f.severity)}">${esc(f.severity)}</td>` +
      `<td>${esc(f.code)}</td><td>${esc(f.detail).slice(0,70)}</td></tr>`).join('')
      || '<tr><td colspan="3" class="muted">no findings</td></tr>';
    $('#hops').innerHTML = ((r.sandbox && r.sandbox.chain) || []).map(h =>
      `<div class="tag">${esc(h.status)} → ${esc(h.url).slice(0,58)}</div>`).join('')
      || '<span class="muted">no redirects observed</span>';
    const shot = r.sandbox && r.sandbox.screenshot_sha256;
    $('#shots').innerHTML = shot
      ? `<div class="tag">sha256:${esc(shot).slice(0,16)}… ` +
        `(${r.sandbox.screenshot_bytes} bytes)</div>`
      : '<span class="muted">no screenshot captured</span>';
  } catch (e) { term('! ' + e.message, 'err'); }
  finally {
    $('#scan-btn').disabled = false;
    setTimeout(() => { $('#scan-bar').style.width = '0'; }, 900);
  }
}

async function runOsint() {
  const target = $('#osint-target').value.trim(); if (!target) return;
  try {
    await api('/api/recon/osint', {method:'POST', body: JSON.stringify({target})});
    loadGraph();
  }
  catch (e) { term('! ' + e.message, 'err'); }
}

async function loadAssets() {
  const d = await api('/api/assets');
  const filter = $('#asset-filter').value.trim().toLowerCase();
  const rows = d.assets.filter(a => !filter ||
    JSON.stringify(a).toLowerCase().includes(filter));
  $('#assets').innerHTML = rows.map(a => {
    const svc = (a.services || []).map(s => `${s.port}/${s.protocol || 'tcp'}`).join(' ');
    return `<tr><td>${esc(a.address)}</td><td>${esc(a.device_class || '-')}</td>` +
           `<td>${esc(a.vendor || '-')}</td><td>${esc(svc) || '-'}</td>` +
           `<td>${esc((a.banner || '').slice(0,40))}</td></tr>`;
  }).join('') || '<tr><td colspan="5" class="muted">no assets discovered</td></tr>';
  $('#asset-count').textContent = rows.length;
}

async function runIot() {
  const target = $('#iot-target').value.trim(); if (!target) return;
  try {
    await api('/api/recon/iot', {method:'POST',
      body: JSON.stringify({target, query: $('#iot-query').value.trim()})});
    loadAssets();
  } catch (e) { term('! ' + e.message, 'err'); }
}

async function vpn(action) {
  try {
    const r = await api('/api/vpn', {method:'POST', body: JSON.stringify({action})});
    renderTunnel(r);
  } catch (e) { term('! ' + e.message, 'err'); }
}

async function killswitch(engage) {
  try {
    const r = await api('/api/killswitch', {method:'POST', body: JSON.stringify({engage})});
    renderKill(r);
  } catch (e) {
    term('! killswitch refused: ' + e.message, 'err');
    alert('Kill-switch refused:\n\n' + e.message);
  }
}

async function agentRun() {
  const goal = $('#agent-goal').value.trim(), target = $('#agent-target').value.trim();
  if (!goal || !target) return;
  $('#agent-btn').disabled = true;
  try {
    const r = await api('/api/agent/run', {method:'POST', body: JSON.stringify({goal, target})});
    term(`= ${r.status}: ${r.succeeded.length} ok, ` +
         `${r.failed.length} failed, ${r.denied.length} denied`);
  } catch (e) { term('! ' + e.message, 'err'); }
  finally { $('#agent-btn').disabled = false; }
}

function term(line, cls) {
  const el = $('#term');
  const span = document.createElement('span');
  span.className = cls || (line.startsWith('$') ? 'cmd' : '');
  span.textContent = line + '\n';
  el.appendChild(span); el.scrollTop = el.scrollHeight;
}

/* ---------- renderers ---------- */
function renderTunnel(t) {
  if (!t || !t.state) return;
  const p = $('#tunnel-pill');
  p.textContent = 'TUNNEL ' + t.state.toUpperCase();
  p.className = 'pill ' + ({up:'on', degraded:'warn', down:'bad'}[t.state] || '');
  $('#tunnel-detail').innerHTML =
    `<div class="kv"><span>interface</span><span>${esc(t.interface)}</span></div>` +
    `<div class="kv"><span>backend</span><span>${esc(t.backend)}</span></div>` +
    `<div class="kv"><span>endpoint</span><span>${esc(t.endpoint) || '-'}</span></div>` +
    `<div class="kv"><span>handshake age</span>` +
    `<span>${t.handshake_age_seconds ?? '-'}</span></div>` +
    `<div class="kv"><span>detail</span><span>${esc(t.detail)}</span></div>`;
}

function renderKill(k) {
  const p = $('#kill-pill');
  p.textContent = 'KILL-SWITCH ' + (k.engaged ? 'ENGAGED' : 'OFF');
  p.className = 'pill ' + (k.engaged ? 'bad' : '');
}

function renderHealth(h) {
  if (!h || !h.grades) return;
  $('#health').innerHTML = Object.entries(h.grades).map(([k, v]) =>
    `<div class="kv"><span>${esc(k)}</span>` +
    `<span class="${v==='ok'?'':'sev-medium'}">${esc(v)}</span></div>`
  ).join('') + `<div class="kv"><span>overall</span><span>${esc(h.overall)}</span></div>`;
  const p = $('#health-pill');
  p.textContent = 'HEALTH ' + String(h.overall).toUpperCase();
  p.className = 'pill ' + ({ok:'on', warn:'warn', critical:'bad'}[h.overall] || '');
  if (h.snapshot && h.snapshot.cpu_percent != null) spark(h.snapshot.cpu_percent);
}

function renderLeaks(l) {
  const p = $('#leak-pill');
  if (!l || !l.verdict) { p.textContent = 'LEAK ?'; p.className = 'pill'; return; }
  p.textContent = 'LEAK ' + l.verdict.toUpperCase();
  p.className = 'pill ' + ({protected:'on', inconclusive:'warn', leaking:'bad'}[l.verdict] || '');
}

/* ---------- websocket ---------- */
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => { $('#ws-pill').textContent = 'LINK UP'; $('#ws-pill').className = 'pill on'; };
  ws.onclose = () => {
    $('#ws-pill').textContent = 'LINK DOWN'; $('#ws-pill').className = 'pill bad';
    setTimeout(connect, 3000);
  };
  ws.onmessage = (ev) => {
    const f = JSON.parse(ev.data);
    if (f.kind === 'snapshot') {
      const s = f.payload;
      renderTunnel(s.tunnel); renderHealth(s.health);
      renderLeaks(s.leaks); renderKill(s.killswitch || {});
      (s.events || []).slice(-20).forEach(e => term(`· ${e.kind}`));
    }
    else if (f.kind === 'tunnel.updated') renderTunnel(f.payload);
    else if (f.kind === 'health.updated') renderHealth(f.payload);
    else if (f.kind === 'leaks.updated') renderLeaks(f.payload);
    else if (f.kind === 'killswitch.updated') renderKill(f.payload);
    else if (f.kind === 'console.line') term(f.payload.line);
    else if (f.kind === 'scan.started') term('· detonating ' + f.payload.url);
    else if (f.kind === 'graph.updated') $('#gstats').textContent =
      `${f.payload.entities} entities · ${f.payload.relationships} relationships`;
  };
}

async function boot() {
  try {
    const s = await api('/api/state');
    $('#scope').textContent = s.config.scope.length
      ? s.config.scope.join(', ') : 'none — every target will be denied';
    $('#mode').textContent = s.config.execute ? 'EXECUTE' : 'DRY RUN';
    $('#mode').className = 'pill ' + (s.config.execute ? 'warn' : '');
    renderTunnel(s.tunnel); renderHealth(s.health);
    renderLeaks(s.leaks); renderKill(s.killswitch || {});
    gauge(0, null); spark(null);
    connect();
    const c = $('#gcanvas');
    c.width = c.clientWidth; c.height = 460;
    c.addEventListener('click', pickNode);
    loadGraph();
  } catch (e) { showGate(); }
}

window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('nav button').forEach(b =>
    b.addEventListener('click', () => tab(b.dataset.tab)));
  $('#login-btn').addEventListener('click', login);
  $('#token').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  $('#scan-btn').addEventListener('click', runScan);
  $('#osint-btn').addEventListener('click', runOsint);
  $('#iot-btn').addEventListener('click', runIot);
  $('#asset-filter').addEventListener('input', loadAssets);
  $('#agent-btn').addEventListener('click', agentRun);
  $('#refresh-graph').addEventListener('click', loadGraph);
  document.querySelectorAll('[data-vpn]').forEach(b =>
    b.addEventListener('click', () => vpn(b.dataset.vpn)));
  $('#kill-on').addEventListener('click', () => killswitch(true));
  $('#kill-off').addEventListener('click', () => killswitch(false));
  if (window.__AUTHED__) { hideGate(); boot(); } else { showGate(); }
});
"""


def render_index(*, authenticated: bool, config: DashboardConfig | None = None) -> str:
    """Render the dashboard shell.

    ``authenticated`` only decides whether the login overlay starts visible.
    It is never the access control -- every data route re-checks the session
    server-side, so a forged flag here reveals nothing.
    """
    interface = config.vpn_interface if config else "wg0"
    host = f"{config.host}:{config.port}" if config else "127.0.0.1:8443"

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC // Security Assistant</title>
<style>{_CSS}</style>
</head><body>

<div id="gate"><div class="box">
  <h2>&#9679; RESTRICTED CONSOLE</h2>
  <p>This console dispatches autonomous agent runs and can alter VPN and
     firewall state. Present the value of <b>DASHBOARD_SECRET_KEY</b>.</p>
  <input id="token" type="password" placeholder="dashboard secret" autocomplete="off">
  <div class="err-text" id="gate-err"></div>
  <div style="margin-top:12px"><button class="act" id="login-btn">AUTHENTICATE</button></div>
</div></div>

<header>
  <div class="brand">SEC<em>//</em>ASSISTANT</div>
  <span class="pill" id="mode">DRY RUN</span>
  <span class="pill" id="ws-pill">LINK…</span>
  <span class="pill" id="tunnel-pill">TUNNEL ?</span>
  <span class="pill" id="health-pill">HEALTH ?</span>
  <span class="pill" id="leak-pill">LEAK ?</span>
  <span class="pill" id="kill-pill">KILL-SWITCH OFF</span>
  <div class="spacer"></div>
  <span class="muted">scope: <span id="scope">—</span></span>
</header>

<nav>
  <button data-tab="graph" class="active">GRAPH</button>
  <button data-tab="assets">ASSETS</button>
  <button data-tab="threat">THREAT</button>
  <button data-tab="network">NETWORK</button>
  <button data-tab="console">CONSOLE</button>
</nav>

<main>
  <section class="view active" id="view-graph">
    <div class="grid g2" style="grid-template-columns:2fr 1fr">
      <div class="card"><h3>OSINT Entity Graph</h3><div>
        <div class="row" style="margin-bottom:10px">
          <input id="osint-target" placeholder="domain to investigate">
          <button class="act" id="osint-btn">COLLECT</button>
          <button class="act" id="refresh-graph">REDRAW</button>
        </div>
        <canvas id="gcanvas" height="460"></canvas>
        <div class="muted" style="margin-top:6px" id="gstats">no entities</div>
      </div></div>
      <div class="card"><h3>Inspector</h3><div>
        <div id="inspector"><span class="muted">Click a node to inspect it.</span></div>
        <div style="margin-top:14px" class="row">
          <a class="act" href="/api/graph/export/json" style="text-decoration:none">EXPORT JSON</a>
          <a class="act" href="/api/graph/export/cypher"
             style="text-decoration:none">EXPORT CYPHER</a>
        </div>
      </div></div>
    </div>
  </section>

  <section class="view" id="view-assets">
    <div class="card"><h3>IoT &amp; Stream Console —
      <span id="asset-count">0</span> assets</h3><div>
      <div class="row" style="margin-bottom:10px">
        <input id="iot-target" placeholder="authorized asset (ip or host)">
        <input id="iot-query" placeholder="optional search query">
        <button class="act" id="iot-btn">DISCOVER</button>
      </div>
      <input id="asset-filter" style="margin-bottom:10px"
             placeholder="filter by port, service, vendor…">
      <table><thead><tr><th>address</th><th>class</th><th>vendor</th>
        <th>services</th><th>banner</th></tr></thead>
        <tbody id="assets"><tr><td colspan="5" class="muted">no assets discovered</td></tr></tbody>
      </table>
    </div></div>
  </section>

  <section class="view" id="view-threat">
    <div class="grid g2">
      <div class="card"><h3>URL Detonation</h3><div>
        <div class="row"><input id="scan-url" placeholder="https://suspicious.example/login">
          <button class="act" id="scan-btn">DETONATE</button></div>
        <div class="bar" style="margin-top:10px"><i id="scan-bar"></i></div>
        <canvas id="gauge" height="150" style="margin-top:12px"></canvas>
      </div></div>
      <div class="card"><h3>Findings</h3><div>
        <table><thead><tr><th>sev</th><th>code</th><th>detail</th></tr></thead>
          <tbody id="findings"><tr>
            <td colspan="3" class="muted">no scan yet</td></tr></tbody></table>
      </div></div>
      <div class="card"><h3>Redirect Chain</h3><div id="hops">
        <span class="muted">no redirects observed</span></div></div>
      <div class="card"><h3>Sandbox Capture</h3><div id="shots">
        <span class="muted">no screenshot captured</span></div></div>
    </div>
  </section>

  <section class="view" id="view-network">
    <div class="grid g3">
      <div class="card"><h3>Tunnel — {interface}</h3><div>
        <div id="tunnel-detail"><span class="muted">no data</span></div>
        <div class="row" style="margin-top:12px">
          <button class="act" data-vpn="status">STATUS</button>
          <button class="act" data-vpn="connect">CONNECT</button>
          <button class="act danger" data-vpn="disconnect">DISCONNECT</button>
        </div>
      </div></div>
      <div class="card"><h3>Kill-Switch</h3><div>
        <p class="muted">Blocks non-VPN traffic. The lockout guard refuses any
          plan that would sever loopback, established connections, the VPN
          endpoint or your admin network.</p>
        <div class="row" style="margin-top:10px">
          <button class="act danger" id="kill-on">ENGAGE</button>
          <button class="act" id="kill-off">RELEASE</button>
        </div>
      </div></div>
      <div class="card"><h3>System Health</h3><div>
        <div id="health"><span class="muted">no data</span></div>
        <canvas id="spark" height="60" style="margin-top:10px"></canvas>
      </div></div>
    </div>
  </section>

  <section class="view" id="view-console">
    <div class="card"><h3>Agent Command Console</h3><div>
      <div class="row" style="margin-bottom:10px">
        <input id="agent-goal" placeholder="goal, e.g. Map the external surface">
        <input id="agent-target" placeholder="authorized target">
        <button class="act" id="agent-btn">DISPATCH</button>
      </div>
      <pre class="term" id="term"></pre>
      <div class="muted" style="margin-top:6px">
        Bound to {host}. Every dispatch runs under the server's authorization
        scope; a target outside it is denied, not escalated.
      </div>
    </div></div>
  </section>
</main>

<script>window.__AUTHED__ = {"true" if authenticated else "false"};</script>
<script>{_JS}</script>
</body></html>
"""
