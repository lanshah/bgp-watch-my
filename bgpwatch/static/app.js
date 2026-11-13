"use strict";
// BGP Watch Malaysia dashboard. All server data is escaped before insertion (it comes from BGP).
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = ["info", "low", "medium", "high", "critical"];
const MYT = 8 * 3600 * 1000;
function fmt(ts, withDate = false) {
  if (!ts) return "-";
  const d = new Date(ts * 1000 + MYT).toISOString();
  return withDate ? d.slice(0, 10) + " " + d.slice(11, 19) : d.slice(11, 19);
}
function dur(s) { if (s == null) return "-"; s = Math.max(0, s); if (s < 90) return Math.round(s) + " s"; if (s < 5400) return Math.round(s / 60) + " min"; return (s / 3600).toFixed(1) + " h"; }
function sev(s) { return `<span class="sev ${esc(s)}">${esc(s)}</span>`; }
function bar(r) { const pct = Math.max(0, Math.min(1, r ?? 1)) * 100; const c = r < 0.2 ? "bad" : r < 0.6 ? "mid" : ""; return `<div class="bar ${c}"><i style="width:${pct.toFixed(1)}%"></i></div>`; }
function pathHtml(path, origin, actor) {
  if (!path || !path.length) return '<span class="muted">-</span>';
  return '<span class="path">' + path.map((h, i) => {
    const v = Array.isArray(h) ? "{" + h.join(",") + "}" : h;
    const cls = (h === actor ? " actor" : "") + (i === path.length - 1 ? " origin" : "");
    return `<span class="asn${cls}">${esc(v)}</span>`;
  }).join("") + "</span>";
}
async function api(p) { const r = await fetch(p, { cache: "no-store" }); return r.json(); }

let summary = null, tab = "overview", feedSince = 0, feedRows = [], paused = false, netNames = {};

const TABS = ["overview", "feed", "prefixes", "alerts", "about"];
function showTab(name) {
  tab = TABS.includes(name) ? name : "overview";
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("active", x.dataset.tab === tab));
  TABS.forEach((t) => ($("tab-" + t).hidden = t !== tab));
  refresh();
}
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => { location.hash = b.dataset.tab; }));
window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));
$("feedPause").onclick = () => { paused = !paused; $("feedPause").textContent = paused ? "Resume" : "Pause"; };
$("feedNet").onchange = $("feedFlag").onchange = () => { feedSince = 0; feedRows = []; refresh(); };
$("pfxNet").onchange = $("pfxSearch").oninput = () => refresh();
$("incStatus").onchange = () => refresh();

function renderHeader(s) {
  const m = s.meta, mode = m.mode || "-";
  const mEl = $("mode");
  mEl.textContent = mode === "live" ? "LIVE" : mode === "synthetic" ? "SYNTHETIC REPLAY" : "REPLAY";
  mEl.className = "badge " + (mode === "live" ? "live" : mode === "synthetic" ? "synthetic" : "replay");
  const ban = $("banner");
  if (mode === "synthetic") { ban.hidden = false; ban.textContent = "SYNTHETIC TEST DATA: fictional networks, documentation ASNs and test prefixes. Not real events."; }
  else if (mode !== "live" && m.bundle) { ban.hidden = false; ban.textContent = "REPLAY of " + (m.bundle.label || m.replay_of || "recording") + (m.bundle.start ? " · recorded " + fmt(m.bundle.start, true) + " MYT" : ""); }
  else ban.hidden = true;
  const c = m.connection, conn = $("conn");
  if (mode === "live" && c) {
    const age = m.last_msg_ts ? s.server_time - m.last_msg_ts : null;
    conn.innerHTML = `<span class="dot ${c.connected ? "on" : "off"}"></span>${c.connected ? "RIS Live connected" : "RIS Live disconnected (" + esc(c.error || "") + ")"}${age != null ? " · last update " + dur(age) + " ago" : ""}`;
  } else if (mode !== "live") {
    conn.innerHTML = `<span class="dot"></span>event time ${fmt(m.event_time, true)} MYT`;
  }
  const counts = m.counts || {}, eng = m.engine || {};
  const openBy = {};
  s.networks.forEach((n) => Object.entries(n.open || {}).forEach(([k, v]) => (openBy[k] = (openBy[k] || 0) + v)));
  const openTxt = SEV.slice().reverse().filter((k) => openBy[k]).map((k) => `${openBy[k]} ${k}`).join(", ") || "none";
  const nPfx = s.networks.reduce((a, n) => a + (n.prefixes || 0), 0);
  $("kpis").innerHTML = [
    [s.networks.length, "networks watched"],
    [nPfx, "prefixes watched"],
    [s.incidents.open || 0, "open incidents (" + openTxt + ")"],
    [(counts.messages || 0).toLocaleString(), "BGP messages processed"],
    [(eng.notifications || 0) + " / " + (eng.findings || 0), "notifications / raw findings"],
    [m.rpki && m.rpki.buildtime ? m.rpki.buildtime.replace("T", " ").slice(0, 16) : "-", "RPKI VRP set (UTC)"],
  ].map(([v, l]) => `<div class="kpi"><div class="v">${esc(v)}</div><div class="l">${esc(l)}</div></div>`).join("");
  $("aboutMeta").textContent = `Baseline built ${m.baseline_built || "-"} from RIS snapshot ${JSON.stringify(m.ris_snapshot_times || [])}. RPKI source ${(m.rpki && m.rpki.source) || "-"}.`;
}

function renderOverview(s, incs) {
  $("networks").innerHTML = s.networks.map((n) => {
    const open = n.open || {};
    const worst = SEV.slice().reverse().find((k) => open[k]);
    const cls = worst === "critical" ? "alarm" : worst === "high" ? "warn" : "";
    const badges = SEV.slice().reverse().filter((k) => open[k]).map((k) => `${sev(k)} ${open[k]}`).join(" ") || '<span class="muted">no open incidents</span>';
    const av = n.avg_visibility;
    return `<div class="card ${cls}"><h3>${esc(n.name)}</h3>
      <div class="sub mono">${esc((n.asns || []).map((a) => "AS" + a).join(" · "))}</div>
      <div class="row"><span>Prefixes watched</span><b>${esc(n.prefixes)}</b></div>
      <div class="row"><span>Average visibility</span><b>${av == null ? "-" : (av * 100).toFixed(1) + " %"}</b></div>${bar(av)}
      <div class="row"><span>Degraded prefixes (&lt; 60 %)</span><b>${esc(n.degraded || 0)}</b></div>
      <div class="row"><span>Updates seen</span><b>${(n.updates || 0).toLocaleString()}</b></div>
      <div class="row"><span>Last update</span><span class="mono">${fmt(n.last_update)}</span></div>
      <div style="margin-top:8px">${badges}</div></div>`;
  }).join("") || '<div class="empty">No networks loaded yet.</div>';
  const open = incs.filter((i) => i.status === "open");
  const loud = open.filter((i) => SEV.indexOf(i.severity) >= 2);
  const quiet = open.length - loud.length;
  const note = quiet ? `<p class="muted">${quiet} info/low incident${quiet > 1 ? "s" : ""} (not paged) are listed in the <a href="#alerts">Alert log</a>.</p>` : "";
  $("openInc").innerHTML = (loud.length ? incTable(loud) : '<div class="empty">No open medium, high or critical incidents. Quiet is normal: real hijacks and leaks are rare.</div>') + note;
}

function incTable(rows) {
  return `<div class="scroll"><table><thead><tr><th>Severity</th><th>Network</th><th>Incident</th><th>First seen (MYT)</th><th>Peers</th><th>Prefixes</th></tr></thead><tbody>` +
    rows.map((i) => `<tr class="clickable" onclick="location.href='/incident.html?id=${Number(i.id)}'"><td>${sev(i.severity)}</td><td>${esc(netNames[i.network] || i.network)}</td>
      <td><a href="/incident.html?id=${Number(i.id)}">${esc(i.summary || i.title)}</a><div class="muted">${esc(i.kind.replace(/_/g, " "))}</div></td>
      <td class="mono">${fmt(i.first_seen, true)}</td><td>${esc(i.peers)}</td><td>${i.prefixes.length}</td></tr>`).join("") + "</tbody></table></div>";
}

async function renderFeed() {
  if (paused) return;
  const q = new URLSearchParams({ since: feedSince, limit: 200 });
  if ($("feedNet").value) q.set("network", $("feedNet").value);
  if ($("feedFlag").checked) q.set("flagged", 1);
  const rows = await api("/api/feed?" + q);
  if (rows.length) { feedSince = Math.max(feedSince, ...rows.map((r) => r.id)); feedRows = rows.concat(feedRows).slice(0, 400); }
  $("feedInfo").textContent = `${feedRows.length} most recent updates shown`;
  $("feed").innerHTML = feedRows.map((u) => {
    let path = []; try { path = JSON.parse(u.path || "[]"); } catch (e) {}
    return `<tr class="${u.flagged ? "flag" : ""}"><td class="mono">${fmt(u.ts, true)}</td><td>${esc(u.network)}</td>
      <td>${u.kind === "A" ? "announce" : '<span class="muted">withdraw</span>'}</td><td class="mono">${esc(u.prefix)}</td>
      <td class="mono">${u.origin ? "AS" + esc(u.origin) : ""}</td><td>${pathHtml(path)}</td><td class="mono muted">${esc(u.peer)}</td></tr>`;
  }).join("") || '<tr><td colspan="7" class="muted">Waiting for BGP updates…</td></tr>';
}

async function renderPrefixes() {
  const net = $("pfxNet").value, f = $("pfxSearch").value.trim();
  const rows = (await api("/api/prefixes" + (net ? "?network=" + encodeURIComponent(net) : ""))).filter((r) => !f || r.prefix.includes(f));
  $("pfx").innerHTML = rows.slice(0, 1500).map((r) => `<tr class="clickable" data-p="${esc(r.prefix)}"><td class="mono">${esc(r.prefix)}</td><td>${esc(r.network)}</td>
    <td>${r.baseline ? bar(r.ratio) : '<span class="muted">no baseline peers</span>'}</td><td>${esc(r.seen)} / ${esc(r.baseline)}${r.baseline ? " (" + (r.ratio * 100).toFixed(0) + " %)" : ""}</td>
    <td>${esc(r.total)}</td><td class="mono muted">${fmt(r.updated)}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">No prefixes.</td></tr>';
  document.querySelectorAll("#pfx tr[data-p]").forEach((tr) => (tr.onclick = () => prefixDetail(tr.dataset.p)));
}

async function prefixDetail(p) {
  const d = await api("/api/prefix?prefix=" + encodeURIComponent(p));
  $("pfxDetail").innerHTML = `<section style="margin-top:14px"><h2>${esc(p)}: last ${d.updates.length} updates</h2><div class="scroll" style="max-height:320px"><table><thead><tr><th>Time (MYT)</th><th>Type</th><th>Origin</th><th>AS path</th><th>RIS peer</th></tr></thead><tbody>` +
    (d.updates.map((u) => { let path = []; try { path = JSON.parse(u.path || "[]"); } catch (e) {} return `<tr class="${u.flagged ? "flag" : ""}"><td class="mono">${fmt(u.ts, true)}</td><td>${u.kind === "A" ? "announce" : "withdraw"}</td><td class="mono">${u.origin ? "AS" + esc(u.origin) : ""}</td><td>${pathHtml(path)}</td><td class="mono muted">${esc(u.peer)}</td></tr>`; }).join("") || '<tr><td colspan="5" class="muted">No updates recorded for this prefix yet (quiet is normal).</td></tr>') +
    "</tbody></table></div></section>";
  $("pfxDetail").scrollIntoView({ behavior: "smooth" });
}

async function renderAlerts() {
  const st = $("incStatus").value;
  const incs = await api("/api/incidents" + (st ? "?status=" + st : ""));
  $("incs").innerHTML = incs.map((i) => `<tr class="clickable" onclick="location.href='/incident.html?id=${Number(i.id)}'"><td>${sev(i.severity)}</td>
    <td class="status-${esc(i.status)}">${esc(i.status)}${i.reopened ? " (reopened " + esc(i.reopened) + "x)" : ""}</td><td>${esc(netNames[i.network] || i.network)}</td>
    <td><a href="/incident.html?id=${Number(i.id)}">${esc(i.summary || i.title)}</a><div class="muted">${esc(i.kind.replace(/_/g, " "))} · ${esc(i.findings)} findings</div></td>
    <td class="mono">${fmt(i.first_seen, true)}</td><td>${dur((i.resolved_at || i.last_seen) - i.first_seen)}</td><td>${esc(i.peers)}</td><td>${i.prefixes.length}</td></tr>`).join("") ||
    '<tr><td colspan="8" class="muted">No incidents recorded.</td></tr>';
  const notes = await api("/api/notifications?limit=200");
  $("notes").innerHTML = notes.map((n) => `<tr><td class="mono">${fmt(n.ts, true)}</td><td>${esc(n.channel)}${n.delivered ? "" : ' <span class="muted">(not delivered' + (n.error ? ": " + esc(n.error) : "") + ")</span>"}</td>
    <td>${sev(n.severity)}</td><td>${esc(n.reason)}</td><td><a href="/incident.html?id=${Number(n.incident_id)}">${esc(n.message)}</a></td></tr>`).join("") ||
    '<tr><td colspan="5" class="muted">No notifications yet.</td></tr>';
}

async function refresh() {
  try {
    summary = await api("/api/summary");
    summary.networks.forEach((n) => (netNames[n.key] = n.name));
    ["feedNet", "pfxNet"].forEach((id) => {
      const sel = $(id);
      if (sel.options.length === 1) summary.networks.forEach((n) => sel.add(new Option(n.name, n.key)));
    });
    renderHeader(summary);
    if (tab === "overview") renderOverview(summary, await api("/api/incidents?status=open"));
    if (tab === "feed") await renderFeed();
    if (tab === "prefixes") await renderPrefixes();
    if (tab === "alerts") await renderAlerts();
  } catch (e) { $("conn").innerHTML = '<span class="dot off"></span>dashboard cannot reach the BGP Watch process'; }
}
setInterval(() => { $("clock").textContent = fmt(Date.now() / 1000, true) + " MYT"; }, 1000);
setInterval(() => { if (tab !== "prefixes") refresh(); }, 3000);
showTab(location.hash.slice(1));
