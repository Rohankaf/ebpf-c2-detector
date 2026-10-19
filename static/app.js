const API = "";
let currentView = "overview";
let lastEventId = 0;
const liveEventRows = [];
const MAX_LIVE_ROWS = 100;

const SEVERITY = {
  "NORMAL": "normal",
  "C2-LIKE BEACONING": "critical",
  "SCANNING-LIKE ACTIVITY": "critical",
  "CONNECTION BURST": "warning",
  "MULTI-DESTINATION ACTIVITY": "warning",
  "DESTINATION CHURN": "warning",
  "FAILED-CONNECTION ANOMALY": "warning",
};
function sevClass(verdict) { return SEVERITY[verdict] || "warning"; }

function chip(verdict) {
  return `<span class="chip ${sevClass(verdict)}">${verdict}</span>`;
}

function fmtTs(ts) {
  if (!ts) return "—";
  return ts.replace("T", " ").replace(/\.\d+\+00:00$/, "").replace("+00:00", "");
}

async function getJSON(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  return res.json();
}

function setActiveNav(view) {
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.dataset.view === view);
  });
}

function navigate(view, param) {
  currentView = view;
  window.location.hash = param ? `${view}/${param}` : view;
}

window.addEventListener("hashchange", renderFromHash);
window.addEventListener("DOMContentLoaded", () => {
  renderFromHash();
  pollStatusBar();
  setInterval(pollStatusBar, 4000);
});

function renderFromHash() {
  const [view, param] = (window.location.hash.replace("#", "") || "overview").split("/");
  currentView = view || "overview";
  setActiveNav(currentView);
  const views = {
    overview: renderOverview,
    live: renderLive,
    alerts: renderAlerts,
    processes: renderProcesses,
    investigations: () => renderInvestigationList(),
    investigation: () => renderInvestigation(param),
    console: () => renderConsole(param),
    status: renderStatus,
  };
  (views[currentView] || renderOverview)();
}

// ---- status bar (always visible) ----
async function pollStatusBar() {
  try {
    const s = await getJSON("/api/system-status");
    document.getElementById("sb-dot").className = "dot " + (s.tracer_running ? "on" : "off");
    document.getElementById("sb-text").textContent =
      `tracer: ${s.tracer_running ? "running" : "stopped"}  ·  uptime ${Math.floor(s.uptime_seconds)}s  ·  ` +
      `${s.processes_tracked} processes  ·  ${s.events_buffered} events buffered` +
      (s.detector_errors > 0 ? `  ·  ⚠ ${s.detector_errors} detector errors` : "");
  } catch (e) {
    document.getElementById("sb-dot").className = "dot off";
    document.getElementById("sb-text").textContent = "backend unreachable: " + e.message;
  }
}

// ---- Overview ----
async function renderOverview() {
  const el = document.getElementById("content");
  el.innerHTML = `<div id="ov-stats" class="stat-row"></div>
    <div class="panel"><div class="panel-header">Recent Alerts</div>
      <div class="panel-body" id="ov-alerts"></div></div>`;
  try {
    const [status, alerts, tree] = await Promise.all([
      getJSON("/api/system-status"), getJSON("/api/alerts"), getJSON("/api/tree")
    ]);
    document.getElementById("ov-stats").innerHTML = `
      <div class="stat-tile"><div class="value">${tree.processes.length}</div><div class="label">Processes tracked</div></div>
      <div class="stat-tile ${alerts.alerts.length ? "alert" : ""}"><div class="value">${alerts.alerts.length}</div><div class="label">Active alerts</div></div>
      <div class="stat-tile"><div class="value">${status.events_buffered}</div><div class="label">Events buffered</div></div>
      <div class="stat-tile"><div class="value">${Math.floor(status.uptime_seconds)}s</div><div class="label">Backend uptime</div></div>`;
    document.getElementById("ov-alerts").innerHTML = alerts.alerts.length
      ? renderAlertTable(alerts.alerts)
      : `<div class="empty-state">No active alerts — all tracked processes are NORMAL.</div>`;
    wireAlertClicks();
  } catch (e) {
    el.innerHTML = `<div class="panel"><div class="panel-body">Failed to load overview: ${e.message}</div></div>`;
  }
}

// ---- Live Telemetry ----
let liveTimer = null;
function renderLive() {
  clearInterval(liveTimer);
  const el = document.getElementById("content");
  el.innerHTML = `<div class="panel"><div class="panel-header">Live Telemetry
      <span class="meta" id="live-count"></span></div>
      <div class="panel-body" style="padding:0"><table id="live-table">
        <thead><tr><th>Time</th><th>PID</th><th>Process</th><th>Event</th>
        <th>Destination</th><th>Port</th><th>Protocol</th><th>Outcome</th></tr></thead>
        <tbody id="live-tbody"></tbody></table></div></div>`;
  lastEventId = 0;
  liveEventRows.length = 0;
  pollLive();
  liveTimer = setInterval(pollLive, 1500);
}
async function pollLive() {
  if (currentView !== "live") { clearInterval(liveTimer); return; }
  try {
    const data = await getJSON(`/api/events?since=${lastEventId}&limit=200`);
    if (!data.events.length) return;
    for (const e of data.events) {
      lastEventId = Math.max(lastEventId, e.id);
      liveEventRows.unshift(e);
    }
    liveEventRows.length = Math.min(liveEventRows.length, MAX_LIVE_ROWS);
    const tbody = document.getElementById("live-tbody");
    if (!tbody) return;
    tbody.innerHTML = liveEventRows.map(e => `
      <tr>
        <td class="mono muted">${fmtTs(e.timestamp)}</td>
        <td class="mono">${e.pid}</td>
        <td>${e.process || "—"}</td>
        <td>${e.event}</td>
        <td class="mono">${e.destination_ip || "—"}</td>
        <td class="mono">${e.destination_port ?? "—"}</td>
        <td>${e.protocol || "—"}</td>
        <td>${e.event === "state_change" ? (e.success ? '<span class="chip normal">established</span>' : '<span class="chip critical">refused/failed</span>') : "—"}</td>
      </tr>`).join("");
    document.getElementById("live-count").textContent = `${liveEventRows.length} shown`;
  } catch (e) { /* transient fetch errors during polling are not fatal */ }
}

// ---- Alerts ----
function renderAlertTable(alerts) {
  return `<table><thead><tr><th>Time</th><th>PID</th><th>Process</th><th>Verdict</th>
    <th>Reason</th><th>Destinations</th></tr></thead><tbody>
    ${alerts.map(a => `
      <tr class="clickable" data-pid="${a.pid}">
        <td class="mono muted">${fmtTs(a.ts)}</td>
        <td class="mono">${a.pid}</td>
        <td>${a.process}</td>
        <td>${chip(a.verdict)}</td>
        <td>${a.reason}</td>
        <td class="mono muted">${(a.destinations || []).slice(0,3).join(", ")}</td>
      </tr>`).join("")}
    </tbody></table>`;
}
function wireAlertClicks() {
  document.querySelectorAll("tr[data-pid]").forEach(row => {
    row.addEventListener("click", () => navigate("investigation", row.dataset.pid));
  });
}
let alertsTimer = null;
function renderAlerts() {
  clearInterval(alertsTimer);
  const el = document.getElementById("content");
  el.innerHTML = `<div class="panel"><div class="panel-header">Alerts
      <span class="meta">non-NORMAL processes, click a row to investigate</span></div>
      <div class="panel-body" id="alerts-body"></div></div>`;
  pollAlerts();
  alertsTimer = setInterval(pollAlerts, 3000);
}
async function pollAlerts() {
  if (currentView !== "alerts") { clearInterval(alertsTimer); return; }
  try {
    const data = await getJSON("/api/alerts");
    document.getElementById("alerts-body").innerHTML = data.alerts.length
      ? renderAlertTable(data.alerts)
      : `<div class="empty-state">No active alerts.</div>`;
    wireAlertClicks();
  } catch (e) { /* ignore transient */ }
}

// ---- Processes ----
let procTimer = null;
function renderProcesses() {
  clearInterval(procTimer);
  const el = document.getElementById("content");
  el.innerHTML = `<div class="panel"><div class="panel-header">Processes
      <span class="meta">all tracked processes, click a row to investigate</span></div>
      <div class="panel-body" id="proc-body"></div></div>`;
  pollProcesses();
  procTimer = setInterval(pollProcesses, 3000);
}
async function pollProcesses() {
  if (currentView !== "processes" && currentView !== "investigations") {
    clearInterval(procTimer); return;
  }
  try {
    const data = await getJSON("/api/tree");
    const rows = data.processes;
    document.getElementById("proc-body").innerHTML = rows.length
      ? `<table><thead><tr><th>PID</th><th>Process</th><th>Verdict</th>
          <th>Destinations seen</th></tr></thead><tbody>
          ${rows.map(p => `
            <tr class="clickable" data-pid="${p.pid}">
              <td class="mono">${p.pid}</td>
              <td>${p.process}</td>
              <td>${chip(p.verdict)}</td>
              <td class="mono muted">${(p.destinations||[]).slice(0,4).join(", ")}</td>
            </tr>`).join("")}
          </tbody></table>`
      : `<div class="empty-state">No processes tracked yet.</div>`;
    wireAlertClicks();
  } catch (e) { /* ignore transient */ }
}

// ---- Investigations (list) ----
function renderInvestigationList() {
  renderProcesses();
  const hdr = document.querySelector("#content .panel-header");
  if (hdr) {
    hdr.innerHTML = `Investigations <span class="meta">click a process to view full investigation detail</span>`;
  }
}
// ---- Investigation detail ----
async function renderInvestigation(pid) {
  const el = document.getElementById("content");
  el.innerHTML = `<div class="back-link" onclick="navigate('processes')">&larr; back to processes</div>
    <div id="inv-body">Loading…</div>`;
  try {
    const d = await getJSON(`/api/investigation/${pid}`);
    const pi = d.proc_info || {};
    el.querySelector("#inv-body").innerHTML = `
      <div class="panel"><div class="panel-header">Process ${d.pid} — ${d.process}
        <span>${chip(d.current_verdict)}
	  <a href="#console/${d.pid}" style="margin-left:10px;font-size:11px;font-weight:400;">Open in Console &rarr;</a>
	</span></div>
        <div class="panel-body">
          <dl class="kv-grid">
            <dt>PID</dt><dd>${d.pid}</dd>
            <dt>Process name</dt><dd>${d.process}</dd>
            <dt>Current verdict</dt><dd>${d.current_verdict}</dd>
            <dt>Executable</dt><dd>${pi.proc_available ? (pi.exe || "unavailable") : "process has exited — not available"}</dd>
            <dt>Command line</dt><dd>${pi.proc_available ? (pi.cmdline || "—") : "process has exited — not available"}</dd>
            <dt>Parent PID</dt><dd>${pi.proc_available ? (pi.ppid ?? "—") : "—"}</dd>
            <dt>Destinations seen</dt><dd>${(d.destinations||[]).join(", ") || "—"}</dd>
          </dl>
        </div></div>

      <div class="panel"><div class="panel-header">Behavioral Timeline &amp; Evidence</div>
        <div class="panel-body">
          ${d.history.map(h => `
            <div class="timeline-item">
              <div class="timeline-ts">${fmtTs(h.ts)}</div>
              <div>${chip(h.verdict)} <span class="timeline-reason">${h.reason || ""}</span></div>
              ${h.observations && h.observations.length ? `
                <ul class="timeline-obs">${h.observations.map(o => `<li>${o}</li>`).join("")}</ul>` : ""}
              ${h.features ? `
                <div class="mono muted" style="font-size:11px;margin-top:6px;">
                  ${Object.entries(h.features).map(([k,v]) => `${k}=${v}`).join("  ")}
                </div>` : ""}
            </div>`).join("")}
        </div></div>
      ${renderSnoopSection(d.snoop)}`;
  } catch (e) {
    el.querySelector("#inv-body").innerHTML =
      `<div class="panel"><div class="panel-body">No telemetry found for PID ${pid} (${e.message}).</div></div>`;
  }
}

// ---- System Status ----
function renderStatus() {
  const el = document.getElementById("content");
  el.innerHTML = `<div class="panel"><div class="panel-header">System Status</div>
    <div class="panel-body" id="status-body">Loading…</div></div>`;
  pollStatusView();
}
async function pollStatusView() {
  try {
    const s = await getJSON("/api/system-status");
    document.getElementById("status-body").innerHTML = `
      <dl class="kv-grid">
        <dt>eBPF tracer</dt><dd>${s.tracer_running ? "running" : "stopped"}</dd>
        <dt>Backend uptime</dt><dd>${Math.floor(s.uptime_seconds)}s</dd>
        <dt>Processes tracked</dt><dd>${s.processes_tracked}</dd>
        <dt>Events buffered</dt><dd>${s.events_buffered}</dd>
        <dt>Detection window</dt><dd>${s.window_seconds}s</dd>
        <dt>Detector errors</dt><dd>${s.detector_errors}</dd>
      </dl>`;
  } catch (e) {
    document.getElementById("status-body").innerHTML = `Backend unreachable: ${e.message}`;
  }
  if (currentView === "status") setTimeout(pollStatusView, 4000);
}
// ---- Investigation Console ----
let consoleHistory = [];

async function renderConsole(initialPid) {
  const el = document.getElementById("content");
  el.innerHTML = `
    <div class="console-shell">
      <div class="console-toolbar">
        <span>Investigation Console</span>
        <span style="flex:1"></span>
        <label>PID <input type="text" id="console-pid" value="${initialPid || ""}" placeholder="optional"></label>
      </div>
      <div class="console-output" id="console-output"></div>
      <div class="console-inputrow">
        <input type="text" id="console-input" placeholder="type a command, e.g. ps -ef --forest, ss -tnp, lsof -p \$PID"
               autocomplete="off" spellcheck="false">
        <button id="console-run">Run</button>
      </div>
    </div>`;

  const input = document.getElementById("console-input");
  const runBtn = document.getElementById("console-run");
  input.addEventListener("keydown", e => { if (e.key === "Enter") runConsoleCommand(); });
  runBtn.addEventListener("click", runConsoleCommand);

  try {
    const data = await getJSON("/api/console/history?limit=100");
    consoleHistory = data.history;
    renderConsoleOutput();
  } catch (e) { /* fresh console, no prior history is fine */ }

  input.focus();
}

function pidOrNull() {
  const v = document.getElementById("console-pid").value.trim();
  return v ? v : null;
}

async function runConsoleCommand() {
  const input = document.getElementById("console-input");
  const runBtn = document.getElementById("console-run");
  const command = input.value;
  if (!command.trim()) return;

  runBtn.disabled = true;
  try {
    const res = await fetch("/api/console/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command, pid: pidOrNull() }),
    });
    const entry = await res.json();
    consoleHistory.push(entry);
    renderConsoleOutput();
    input.value = "";
  } catch (e) {
    consoleHistory.push({
      id: "?", command, pid: pidOrNull(), ts: new Date().toISOString(),
      status: "error", returncode: null, stdout: "", stderr: "request failed: " + e.message,
      duration_ms: 0,
    });
    renderConsoleOutput();
  } finally {
    runBtn.disabled = false;
    input.focus();
  }
}

function renderConsoleOutput() {
  const out = document.getElementById("console-output");
  if (!out) return;
  out.innerHTML = consoleHistory.map(e => `
    <div class="console-entry">
      <div class="console-prompt">$ ${escapeHtml(e.command)}${e.pid ? `<span class="pid-tag">pid:${e.pid}</span>` : ""}
        <span class="console-meta console-status-${e.status}">${e.status}${e.returncode !== null && e.returncode !== undefined ? ` (exit ${e.returncode})` : ""} · ${e.duration_ms}ms</span>
      </div>
      ${e.stdout ? `<pre class="console-stdout">${escapeHtml(e.stdout)}</pre>` : ""}
      ${e.stderr ? `<pre class="console-stderr">${escapeHtml(e.stderr)}</pre>` : ""}
    </div>`).join("");
  out.scrollTop = out.scrollHeight;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ---- Snoop enrichment section (Investigation view only) ----
function renderSnoopSection(snoop) {
  if (!snoop || !snoop.available) {
    return `<div class="panel"><div class="panel-header">Extended Investigation Data</div>
      <div class="panel-body"><span class="muted">Enrichment data is not available for this process.</span></div></div>`;
  }

  const p = snoop.process || {};
  const r = snoop.resources || {};
  const net = snoop.network || {};
  const k = snoop.kernel || {};
  const files = snoop.files || [];
  const tree = snoop.tree || {};
  const env = snoop.environment || {};

  const listRows = (arr, cols) => arr.length
    ? `<table><tbody>${arr.map(item => `<tr>${cols.map(c => `<td class="mono">${item[c] ?? "—"}</td>`).join("")}</tr>`).join("")}</tbody></table>`
    : `<span class="muted">None observed.</span>`;

  return `
    <div class="panel"><div class="panel-header">Process</div>
      <div class="panel-body"><dl class="kv-grid">
        <dt>Name</dt><dd>${p.name ?? "—"}</dd>
        <dt>Command line</dt><dd>${p.cmdline ?? "—"}</dd>
        <dt>Executable</dt><dd>${p.exe ?? "—"}</dd>
        <dt>State</dt><dd>${p.state ?? "—"}</dd>
        <dt>PPID</dt><dd>${p.ppid ?? "—"}</dd>
        <dt>UID / GID</dt><dd>${p.uid ?? "—"} / ${p.gid ?? "—"}</dd>
        <dt>Started</dt><dd>${p.started ?? "—"}</dd>
        <dt>Threads</dt><dd>${p.threads ?? "—"}</dd>
      </dl></div></div>

    <div class="panel"><div class="panel-header">Resources</div>
      <div class="panel-body"><dl class="kv-grid">
        <dt>CPU</dt><dd>${r.cpu_percent ?? "—"}</dd>
        <dt>Memory RSS</dt><dd>${r.memory_rss_kb ?? "—"} KB</dd>
        <dt>Memory VSZ</dt><dd>${r.memory_vsz_kb ?? "—"} KB</dd>
        <dt>Open FDs</dt><dd>${r.fd_count ?? "—"}</dd>
      </dl></div></div>

    <div class="panel"><div class="panel-header">Network Sockets</div>
      <div class="panel-body">
        <div class="muted" style="margin-bottom:4px;font-size:11px;">Listening</div>
        ${listRows(net.listening, ["protocol", "local_address"])}
        <div class="muted" style="margin:10px 0 4px;font-size:11px;">Connections</div>
        ${listRows(net.connections, ["protocol", "local_address", "remote_address", "state"])}
      </div></div>

    <div class="panel"><div class="panel-header">Kernel Context</div>
      <div class="panel-body"><dl class="kv-grid">
        <dt>Scheduler</dt><dd>${k.scheduler ?? "—"}</dd>
        <dt>OOM score</dt><dd>${k.oom_score ?? "—"}</dd>
        <dt>Cgroup</dt><dd>${k.cgroup ?? "—"}</dd>
        <dt>Namespaces</dt><dd>${Array.isArray(k.namespaces) ? k.namespaces.join(", ") : (k.namespaces ?? "—")}</dd>
        <dt>Seccomp</dt><dd>${k.seccomp ?? "—"}</dd>
        <dt>Capabilities</dt><dd>${Array.isArray(k.capabilities) ? k.capabilities.join(", ") : (k.capabilities ?? "—")}</dd>
      </dl></div></div>

    <div class="panel"><div class="panel-header">Open Files</div>
      <div class="panel-body">${listRows(files, ["fd", "type", "path"])}</div></div>

    <div class="panel"><div class="panel-header">Process Tree</div>
      <div class="panel-body">
        <div class="muted" style="margin-bottom:4px;font-size:11px;">Child processes</div>
        ${listRows(tree.ancestors, ["pid", "name"])}
      </div></div>

    <div class="panel"><div class="panel-header">Environment</div>
      <div class="panel-body mono" style="font-size:11px;white-space:pre-wrap;">
        ${Object.keys(env).length ? Object.entries(env).map(([k2,v2]) => `${k2}=${v2}`).join("\n") : '<span class="muted">None available.</span>'}
      </div></div>`;
}








