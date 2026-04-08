let authToken = sessionStorage.getItem('pd_token');
if (!authToken) window.location.href = 'login.html';

// ── API helper ─────────────────────────────────────────────
async function apiCall(method, path, body) {
  const opts = { method, headers: { 'Authorization': 'Bearer ' + authToken } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    authToken = null;
    sessionStorage.removeItem('pd_token');
    window.location.href = 'login.html';
    throw new Error('unauthorized');
  }
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function setMsg(id, text, isError) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg ' + (isError ? 'err' : 'ok');
}

// ── Tab switching ──────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).style.display = 'block';
  });
});

// ── Load all config ────────────────────────────────────────
async function loadConfig() {
  // Unified proxy tab: input + output
  const inp = await apiCall('GET', '/api/config/input');
  if (inp.ok) {
    document.getElementById('inputType').value = inp.data.input_type || 'http';
    document.getElementById('vpsIp').value = inp.data.vps_ip || '';
    document.getElementById('startPort').value = inp.data.start_port || 30001;
    const lines = (inp.data.proxies || []).map(p => {
      let s = p.host + ':' + p.port;
      if (p.user) s += ':' + p.user + ':' + p.pass;
      return s;
    });
    document.getElementById('inputList').value = lines.join('\n');
    renderMappingTable(inp.data.mapping || []);
  }
  // Status
  const st = await apiCall('GET', '/api/status');
  if (st.ok) {
    document.getElementById('statusBadge').textContent =
      st.data.alive_count + '/' + st.data.proxy_count + ' alive · ' + (st.data.active_ports||[]).length + ' ports';
  }
  // Bypass domains
  loadBypassDomains();
  // Extensions
  loadExtensions();
  // Resource proxy
  loadResourceProxy();
  // Block
  loadBlockDomains();
}

function renderMappingTable(mapping) {
  const tbody = document.getElementById('mappingTableBody');
  const countEl = document.getElementById('proxyCount');
  if (!mapping || mapping.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#94a3b8">Chua co proxy nao. Nhap proxy vao o tren va nhan Save & Apply.</td></tr>';
    countEl.textContent = '';
    return;
  }
  countEl.textContent = '(' + mapping.length + ' proxies)';
  tbody.innerHTML = mapping.map((m, i) => {
    const inputStr = m.user ? m.host + ':' + m.port + ':' + m.user + ':***' : m.host + ':' + m.port;
    return '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td><code>' + inputStr + '</code></td>' +
      '<td>' + (m.type || 'http') + '</td>' +
      '<td>' + m.output_port + '</td>' +
      '<td><code>' + m.output_addr + '</code></td>' +
      '</tr>';
  }).join('');
}

// ── Proxy (unified input + output) ────────────────────────
document.getElementById('saveInputBtn').addEventListener('click', async () => {
  const body = {
    input_type: document.getElementById('inputType').value,
    raw_text: document.getElementById('inputList').value,
    vps_ip: document.getElementById('vpsIp').value,
    start_port: parseInt(document.getElementById('startPort').value, 10),
  };
  const r = await apiCall('POST', '/api/config/input', body);
  if (!r.ok) {
    const errs = (r.data.errors || []).map(e => 'line ' + e.line + ': ' + e.reason).join('; ');
    setMsg('inputMsg', errs || r.data.error || 'Save failed', true);
    return;
  }
  setMsg('inputMsg', 'Saved ' + r.data.count + ' proxies → ' + r.data.count + ' output ports', false);
  loadConfig();
});

document.getElementById('copyBtn').addEventListener('click', async () => {
  const inp = await apiCall('GET', '/api/config/input');
  if (!inp.ok || !inp.data.mapping || inp.data.mapping.length === 0) {
    setMsg('inputMsg', 'Khong co output de copy', true);
    return;
  }
  const text = inp.data.mapping.map(m => m.output_addr).join('\n');
  navigator.clipboard.writeText(text).then(
    () => setMsg('inputMsg', 'Copied ' + inp.data.mapping.length + ' output addresses', false),
    () => setMsg('inputMsg', 'Copy failed', true)
  );
});

// ── Logout ─────────────────────────────────────────────────
document.getElementById('logoutBtn').addEventListener('click', () => {
  authToken = null;
  sessionStorage.removeItem('pd_token');
  window.location.href = 'login.html';
});

// ── Bypass Domains ─────────────────────────────────────────
async function loadBypassDomains() {
  const r = await apiCall('GET', '/api/config/bypass/domains');
  if (!r.ok) return;
  document.getElementById('bypassAction').value = r.data.default_action || 'direct';
  const lines = (r.data.rules || []).map(r => r.pattern).filter(Boolean);
  document.getElementById('bypassDomainList').value = lines.join('\n');
}

document.getElementById('saveBypassDomainsBtn').addEventListener('click', async () => {
  const body = {
    default_action: document.getElementById('bypassAction').value,
    raw_text: document.getElementById('bypassDomainList').value,
  };
  const r = await apiCall('POST', '/api/config/bypass/domains', body);
  if (!r.ok) { setMsg('bypassDomainMsg', r.data.error || 'Save failed', true); return; }
  setMsg('bypassDomainMsg', 'Saved ' + r.data.count + ' rules', false);
});

// ── Presets ────────────────────────────────────────────────
const PRESETS = {
  google: ['*.google.com','*.googleapis.com','*.gstatic.com','*.googlevideo.com','*.youtube.com','*.ytimg.com','*.ggpht.com','*.googleusercontent.com'],
  microsoft: ['*.microsoft.com','*.microsoftonline.com','*.windows.net','*.office.com','*.office365.com','*.live.com','*.outlook.com','*.azure.com'],
  apple: ['*.apple.com','*.icloud.com','*.mzstatic.com','*.cdn-apple.com','*.itunes.com'],
  cdn: ['*.cloudflare.com','*.cloudfront.net','*.akamaized.net','*.fastly.net','*.jsdelivr.net','*.unpkg.com','*.cdnjs.cloudflare.com'],
  social: ['*.facebook.com','*.fbcdn.net','*.twitter.com','*.twimg.com','*.instagram.com','*.tiktok.com','*.reddit.com'],
};

function appendPreset(name) {
  const list = PRESETS[name];
  if (!list) return;
  const ta = document.getElementById('bypassDomainList');
  const cur = ta.value.trim();
  const existing = new Set(cur.split('\n').map(l => l.trim()).filter(Boolean));
  const toAdd = list.filter(d => !existing.has(d));
  if (toAdd.length === 0) return;
  ta.value = (cur ? cur + '\n' : '') + toAdd.join('\n');
}

// ── Extensions ─────────────────────────────────────────────
let extensionData = [];

async function loadExtensions() {
  const r = await apiCall('GET', '/api/config/bypass/extensions');
  if (!r.ok) return;
  document.getElementById('extAction').value = r.data.default_action || 'direct';
  extensionData = [];
  const groups = r.data.groups || {};
  for (const [group, exts] of Object.entries(groups)) {
    for (const ext of exts) {
      extensionData.push(ext);
    }
  }
  renderExtGroups();
}

function renderExtGroups() {
  const container = document.getElementById('extGroups');
  container.innerHTML = '';
  const grouped = {};
  extensionData.forEach(e => {
    if (!grouped[e.group]) grouped[e.group] = [];
    grouped[e.group].push(e);
  });
  for (const [group, exts] of Object.entries(grouped)) {
    const section = document.createElement('div');
    section.className = 'ext-group';
    const hdr = document.createElement('div');
    hdr.className = 'ext-group-header';
    hdr.innerHTML = '<span class="ext-group-name">' + group + '</span>' +
      '<button class="btn btn-xs" onclick="toggleGroup(\'' + group + '\',true)">All</button>' +
      '<button class="btn btn-xs" onclick="toggleGroup(\'' + group + '\',false)">None</button>';
    section.appendChild(hdr);
    const chips = document.createElement('div');
    chips.className = 'chip-wrap';
    exts.forEach(ext => {
      const chip = document.createElement('span');
      chip.className = 'chip ' + (ext.enabled ? 'active' : 'inactive');
      chip.textContent = ext.extension;
      chip.onclick = () => { toggleExtension(ext.extension); };
      chips.appendChild(chip);
    });
    section.appendChild(chips);
    container.appendChild(section);
  }
}

function toggleExtension(ext) {
  extensionData.forEach(e => { if (e.extension === ext) e.enabled = !e.enabled; });
  renderExtGroups();
}

function toggleGroup(group, state) {
  extensionData.forEach(e => { if (e.group === group) e.enabled = state; });
  renderExtGroups();
}

function addCustomExt() {
  const inp = document.getElementById('customExt');
  const ext = inp.value.trim().toLowerCase().replace(/^\./, '');
  if (!ext) return;
  if (extensionData.find(e => e.extension === ext)) { inp.value = ''; return; }
  extensionData.push({ extension: ext, group: 'custom', action: '', enabled: true });
  inp.value = '';
  renderExtGroups();
}

document.getElementById('saveExtBtn').addEventListener('click', async () => {
  const body = {
    default_action: document.getElementById('extAction').value,
    extensions: extensionData,
  };
  const r = await apiCall('POST', '/api/config/bypass/extensions', body);
  if (!r.ok) { setMsg('extMsg', r.data.error || 'Save failed', true); return; }
  setMsg('extMsg', 'Saved', false);
});

// ── Resource Proxy ─────────────────────────────────────────
async function loadResourceProxy() {
  const r = await apiCall('GET', '/api/config/resource-proxy');
  if (!r.ok) return;
  if (r.data.configured) {
    document.getElementById('resHost').value = r.data.host || '';
    document.getElementById('resPort').value = r.data.port || '';
    document.getElementById('resType').value = r.data.type || 'http';
    document.getElementById('resUser').value = r.data.user || '';
  }
}

document.getElementById('saveResBtn').addEventListener('click', async () => {
  const body = {
    host: document.getElementById('resHost').value,
    port: parseInt(document.getElementById('resPort').value, 10) || 0,
    type: document.getElementById('resType').value,
    user: document.getElementById('resUser').value,
    pass: document.getElementById('resPass').value,
  };
  const r = await apiCall('POST', '/api/config/resource-proxy', body);
  if (!r.ok) { setMsg('resMsg', r.data.error || 'Save failed', true); return; }
  setMsg('resMsg', 'Saved', false);
});

// ── Block Domains ──────────────────────────────────────────
async function loadBlockDomains() {
  const r = await apiCall('GET', '/api/config/block/domains');
  if (!r.ok) return;
  document.getElementById('blockAction').value = r.data.default_action || '403';
  const lines = (r.data.rules || []).map(r => r.pattern).filter(Boolean);
  document.getElementById('blockDomainList').value = lines.join('\n');
}

document.getElementById('saveBlockBtn').addEventListener('click', async () => {
  const body = {
    default_action: document.getElementById('blockAction').value,
    raw_text: document.getElementById('blockDomainList').value,
  };
  const r = await apiCall('POST', '/api/config/block/domains', body);
  if (!r.ok) { setMsg('blockMsg', r.data.error || 'Save failed', true); return; }
  setMsg('blockMsg', 'Saved ' + r.data.count + ' rules', false);
});

// ── Whitelist ──────────────────────────────────────────────
async function loadWhitelist() {
  const r = await apiCall('GET', '/api/config/whitelist');
  if (!r.ok) return;
  document.getElementById('wlEnabled').checked = r.data.enabled;
  document.getElementById('abEnabled').checked = r.data.auto_ban?.enabled ?? true;
  document.getElementById('abMaxAttempts').value = r.data.auto_ban?.max_attempts ?? 10;
  document.getElementById('abBanDuration').value = r.data.auto_ban?.ban_duration_sec ?? 3600;
  renderWhitelistTable(r.data.entries || []);

  const ip = await apiCall('GET', '/api/config/whitelist/my-ip');
  if (ip.ok) document.getElementById('myIpDisplay').textContent = 'Your IP: ' + ip.data.ip;

  const banned = await apiCall('GET', '/api/config/whitelist/banned');
  if (banned.ok) {
    const ips = banned.data.ips || [];
    document.getElementById('bannedList').textContent = ips.length ? ips.join(', ') : 'None';
  }
}

function renderWhitelistTable(entries) {
  const c = document.getElementById('wlTable');
  if (!entries.length) { c.innerHTML = '<p style="color:#8a8ab0;font-size:13px">No entries</p>'; return; }
  let html = '<table class="mini-table"><tr><th>IP</th><th>Type</th><th>Note</th><th>Expires</th><th></th></tr>';
  entries.forEach(e => {
    const exp = e.expires_at ? new Date(e.expires_at * 1000).toLocaleString() : 'Never';
    html += '<tr><td>' + e.ip + '</td><td>' + (e.type||'single') + '</td><td>' + (e.note||'') + '</td><td>' + exp + '</td>';
    html += '<td><button class="btn btn-xs" style="background:#dc2626;color:white" onclick="removeWhitelistIP(\'' + e.ip + '\')">X</button></td></tr>';
  });
  html += '</table>';
  c.innerHTML = html;
}

document.getElementById('addWlBtn').addEventListener('click', async () => {
  const body = {
    ip: document.getElementById('wlNewIp').value,
    note: document.getElementById('wlNewNote').value,
    expires_in_sec: parseInt(document.getElementById('wlNewExpiry').value, 10),
  };
  const r = await apiCall('POST', '/api/config/whitelist/add', body);
  if (!r.ok) { setMsg('wlMsg', r.data.error || 'Failed', true); return; }
  setMsg('wlMsg', 'Added', false);
  document.getElementById('wlNewIp').value = '';
  document.getElementById('wlNewNote').value = '';
  loadWhitelist();
});

async function removeWhitelistIP(ip) {
  await apiCall('DELETE', '/api/config/whitelist/remove', { ip });
  loadWhitelist();
}

document.getElementById('addMyIpBtn').addEventListener('click', async () => {
  const ip = await apiCall('GET', '/api/config/whitelist/my-ip');
  if (!ip.ok) return;
  const r = await apiCall('POST', '/api/config/whitelist/add', { ip: ip.data.ip, note: 'My IP', expires_in_sec: 0 });
  if (!r.ok) { setMsg('wlMsg', r.data.error || 'Failed', true); return; }
  setMsg('wlMsg', 'Added ' + ip.data.ip, false);
  loadWhitelist();
});

document.getElementById('saveWlConfigBtn').addEventListener('click', async () => {
  const body = {
    enabled: document.getElementById('wlEnabled').checked,
    entries: [], // Keep existing entries on server side.
    auto_ban: {
      enabled: document.getElementById('abEnabled').checked,
      max_attempts: parseInt(document.getElementById('abMaxAttempts').value, 10),
      ban_duration_sec: parseInt(document.getElementById('abBanDuration').value, 10),
    },
  };
  // Re-fetch entries so we don't lose them.
  const cur = await apiCall('GET', '/api/config/whitelist');
  if (cur.ok) body.entries = cur.data.entries || [];
  const r = await apiCall('POST', '/api/config/whitelist', body);
  if (!r.ok) { setMsg('wlConfigMsg', r.data.error || 'Failed', true); return; }
  setMsg('wlConfigMsg', 'Saved', false);
});

// ── Auto Bypass ────────────────────────────────────────────
async function loadAutoBypass() {
  const r = await apiCall('GET', '/api/config/auto-bypass');
  if (!r.ok) return;
  document.getElementById('abpEnabled').checked = r.data.enabled;
  const th = r.data.size_threshold || 1048576;
  if (th >= 1048576) {
    document.getElementById('abpThresholdVal').value = th / 1048576;
    document.getElementById('abpThresholdUnit').value = '1048576';
  } else {
    document.getElementById('abpThresholdVal').value = th / 1024;
    document.getElementById('abpThresholdUnit').value = '1024';
  }
  const windowSec = r.data.time_window_sec || 120;
  document.getElementById('abpWindowMin').value = Math.round(windowSec / 60) || 2;
}

document.getElementById('saveAbpBtn').addEventListener('click', async () => {
  const unit = parseInt(document.getElementById('abpThresholdUnit').value, 10);
  const val = parseFloat(document.getElementById('abpThresholdVal').value);
  const windowMin = parseInt(document.getElementById('abpWindowMin').value, 10) || 2;
  const body = {
    enabled: document.getElementById('abpEnabled').checked,
    size_threshold: Math.round(val * unit),
    time_window_sec: windowMin * 60,
    action: 'direct',
    strategy: 'stream',
    predict_enabled: true,
  };
  const r = await apiCall('POST', '/api/config/auto-bypass', body);
  if (!r.ok) { setMsg('abpMsg', r.data.error || 'Failed', true); return; }
  setMsg('abpMsg', 'Saved', false);
});

// ── Auto Bypass Stats ──────────────────────────────────────
async function refreshAbpStats() {
  const r = await apiCall('GET', '/api/auto-bypass/stats');
  if (!r.ok) return;
  document.getElementById('abpTotal').textContent = r.data.total || 0;
  const tbody = document.getElementById('abpEventsBody');
  tbody.innerHTML = '';
  const events = (r.data.events || []).reverse();
  events.forEach(ev => {
    const tr = document.createElement('tr');
    tr.style.color = '#4ade80';
    const ts = new Date(ev.time).toLocaleTimeString();
    tr.innerHTML = '<td>' + ts + '</td><td>' + (ev.port||'') + '</td><td style="font-weight:600">' + ev.domain +
      '</td><td>' + formatBytes(ev.size) + '</td><td>' + formatBytes(ev.threshold) +
      '</td><td><span style="background:#166534;color:#4ade80;padding:2px 8px;border-radius:4px;font-weight:600">BYPASSED</span></td>' +
      '<td><button class="btn btn-sm" style="background:#f59e0b;color:#000;padding:2px 6px;font-size:11px" onclick="addToForceProxy(\'' +
      ev.domain.replace(/'/g, "\\'") + '\')">→ Force Proxy</button></td>';
    tbody.appendChild(tr);
  });
}

async function addToForceProxy(domain) {
  const r = await apiCall('POST', '/api/auto-bypass/force-proxy', { domain });
  if (!r.ok) { alert('Failed: ' + (r.data.error||'')); return; }
  refreshAbpStats();
  loadForceProxy();
}

document.getElementById('abpRefreshBtn').addEventListener('click', refreshAbpStats);
document.getElementById('abpClearBtn').addEventListener('click', async () => {
  await apiCall('POST', '/api/auto-bypass/clear');
  refreshAbpStats();
});

// ── Force Proxy ────────────────────────────────────────────
async function loadForceProxy() {
  const r = await apiCall('GET', '/api/config/force-proxy');
  if (!r.ok) return;
  const lines = (r.data.rules || []).map(r => r.pattern).filter(Boolean);
  document.getElementById('forceProxyList').value = lines.join('\n');
}

document.getElementById('saveForceProxyBtn').addEventListener('click', async () => {
  const body = { raw_text: document.getElementById('forceProxyList').value };
  const r = await apiCall('POST', '/api/config/force-proxy', body);
  if (!r.ok) { setMsg('forceProxyMsg', r.data.error || 'Failed', true); return; }
  let msg = 'Saved ' + r.data.count + ' rules';
  if (r.data.removed_bypass > 0) msg += ' — removed ' + r.data.removed_bypass + ' from Bypass Rules';
  setMsg('forceProxyMsg', msg, false);
});

// ── Bandwidth Budget ───────────────────────────────────────
async function loadBudgetConfig() {
  const r = await apiCall('GET', '/api/config/bandwidth-budget');
  if (!r.ok) return;
  document.getElementById('budgetEnabled').checked = r.data.enabled;
  document.getElementById('budgetDailyGB').value = ((r.data.daily_limit_bytes || 0) / 1073741824).toFixed(1);
  document.getElementById('budgetDomainMB').value = Math.round((r.data.domain_hourly_limit || 0) / 1048576);
  document.getElementById('budgetWarnPct').value = r.data.warning_percent || 80;
  document.getElementById('budgetOverAction').value = r.data.over_limit_action || 'direct';
}

document.getElementById('saveBudgetBtn').addEventListener('click', async () => {
  const body = {
    enabled: document.getElementById('budgetEnabled').checked,
    daily_limit_bytes: Math.round(parseFloat(document.getElementById('budgetDailyGB').value) * 1073741824),
    domain_hourly_limit: parseInt(document.getElementById('budgetDomainMB').value, 10) * 1048576,
    warning_percent: parseInt(document.getElementById('budgetWarnPct').value, 10),
    over_limit_action: document.getElementById('budgetOverAction').value,
  };
  const r = await apiCall('POST', '/api/config/bandwidth-budget', body);
  if (!r.ok) { setMsg('budgetMsg', r.data.error || 'Failed', true); return; }
  setMsg('budgetMsg', 'Saved', false);
});

// ── Bandwidth Stats ────────────────────────────────────────
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

let bwInterval = null;

async function refreshBandwidth() {
  const r = await apiCall('GET', '/api/bandwidth/status');
  if (!r.ok) return;
  document.getElementById('bwProxy').textContent = formatBytes(r.data.daily_proxy_bytes || 0);
  document.getElementById('bwDirect').textContent = formatBytes(r.data.daily_direct_bytes || 0);
  document.getElementById('bwSaving').textContent = formatBytes(r.data.saving_today_bytes || 0);
  document.getElementById('bwBudget').textContent = (r.data.budget_percent || 0) + '%';

  const bar = document.getElementById('budgetBar');
  const pct = Math.min(r.data.budget_percent || 0, 100);
  bar.style.width = pct + '%';
  bar.className = 'progress-fill' + (pct >= 90 ? ' danger' : pct >= 70 ? ' warning' : '');

  // Snapshot for pie + table.
  const snap = await apiCall('GET', '/api/bandwidth/snapshot');
  if (snap.ok) {
    drawPieChart(snap.data.total_proxy_bytes || 0, snap.data.total_direct_bytes || 0, snap.data.total_blocked_reqs || 0);
    renderTopDomains(snap.data.top_domains_by_bytes || []);
  }
}

function drawPieChart(proxy, direct, blocked) {
  const total = proxy + direct + (blocked * 100); // blocked is count, give it token size
  if (total === 0) { document.getElementById('pieChart').innerHTML = ''; return; }
  const svg = document.getElementById('pieChart');
  const slices = [
    { val: proxy, color: '#4f46e5', label: 'Proxy' },
    { val: direct, color: '#059669', label: 'Direct' },
    { val: blocked * 100, color: '#dc2626', label: 'Blocked' },
  ].filter(s => s.val > 0);

  let html = '<circle cx="18" cy="18" r="15.915" fill="none" stroke="#0f1024" stroke-width="3.8"></circle>';
  let offset = 25;
  const legend = [];
  slices.forEach(s => {
    const pct = (s.val / total) * 100;
    html += '<circle cx="18" cy="18" r="15.915" fill="none" stroke="' + s.color + '" stroke-width="3.8" stroke-dasharray="' + pct + ' ' + (100 - pct) + '" stroke-dashoffset="-' + offset + '"></circle>';
    offset += pct;
    legend.push('<span style="color:' + s.color + '">' + s.label + ' ' + pct.toFixed(0) + '%</span>');
  });
  svg.innerHTML = html;
  document.getElementById('pieLegend').innerHTML = legend.join(' · ');
}

function renderTopDomains(domains) {
  const c = document.getElementById('topDomainsTable');
  if (!domains.length) { c.innerHTML = '<p style="color:#8a8ab0;font-size:13px">No data yet</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Domain</th><th>Route</th><th>Bytes</th><th>Requests</th><th>Avg Size</th></tr>';
  domains.forEach(d => {
    const rt = d.route_type || 'proxy';
    const color = rt === 'direct' ? '#4ade80' : rt === 'mixed' ? '#fbbf24' : '#818cf8';
    const badge = '<span style="color:' + color + ';font-weight:600">' + rt.toUpperCase() + '</span>';
    html += '<tr><td>' + d.domain + '</td><td>' + badge + '</td><td>' + formatBytes(d.bytes_total) + '</td><td>' + d.request_count + '</td><td>' + formatBytes(d.avg_size) + '</td></tr>';
  });
  html += '</table>';
  c.innerHTML = html;
}

document.getElementById('clearBwBtn').addEventListener('click', async () => {
  if (!confirm('Clear tat ca bandwidth data?')) return;
  const r = await apiCall('POST', '/api/bandwidth/clear');
  if (r.ok) {
    setMsg('bwClearMsg', 'Data cleared', false);
    refreshBandwidth();
  } else {
    setMsg('bwClearMsg', 'Clear failed', true);
  }
});

// Tab-aware auto-refresh for bandwidth.
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (bwInterval) { clearInterval(bwInterval); bwInterval = null; }
    if (btn.dataset.tab === 'tab-bandwidth') {
      refreshBandwidth();
      bwInterval = setInterval(refreshBandwidth, 5000);
    }
  });
});

// ── Report Tab ─────────────────────────────────────────────
let liveWS = null;
let liveTrafficRows = {};
let reportInterval = null;

function wsConnect() {
  if (liveWS && liveWS.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  liveWS = new WebSocket(proto + '//' + location.host + '/ws/live-traffic?token=' + authToken);
  liveWS.onopen = () => { document.getElementById('wsStatus').textContent = 'connected'; document.getElementById('wsStatus').style.color = '#4ade80'; };
  liveWS.onclose = () => { document.getElementById('wsStatus').textContent = 'disconnected'; document.getElementById('wsStatus').style.color = '#f87171'; };
  liveTrafficRows = {};
  liveWS.onmessage = (evt) => {
    try {
      const e = JSON.parse(evt.data);
      const tbody = document.getElementById('liveTrafficBody');
      const domain = e.domain || 'unknown';
      const port = e.listen_port || 0;
      const route = (e.route_type||'').toLowerCase();
      const key = domain + '|' + port + '|' + route;
      const bytes = (e.bytes_sent||0) + (e.bytes_recv||0);

      if (liveTrafficRows[key]) {
        // Update existing row.
        const row = liveTrafficRows[key];
        row.hits++;
        row.bytes += bytes;
        row.latency = Math.max(row.latency, e.latency_ms||0);
        row.ts = new Date(e.timestamp).toLocaleTimeString();
        if (e.error) row.error = e.error;
        row.tr.querySelector('.lt-time').textContent = row.ts;
        row.tr.querySelector('.lt-hits').textContent = row.hits;
        row.tr.querySelector('.lt-latency').textContent = row.latency + 'ms';
        row.tr.querySelector('.lt-bytes').textContent = formatBytes(row.bytes);
        if (e.error) row.tr.querySelector('.lt-error').textContent = e.error;
        // Move to top.
        tbody.insertBefore(row.tr, tbody.firstChild);
        return;
      }

      // New row.
      const tr = document.createElement('tr');
      const ts = new Date(e.timestamp).toLocaleTimeString();
      const rowColor = route === 'direct' ? '#4ade80' : route === 'proxy' ? '#f59e0b' : '#e2e8f0';
      tr.style.color = rowColor;
      const routeBadge = route === 'direct'
        ? '<span style="background:#166534;color:#4ade80;padding:2px 6px;border-radius:4px;font-weight:600">DIRECT</span>'
        : route === 'proxy'
        ? '<span style="background:#92400e;color:#fbbf24;padding:2px 6px;border-radius:4px;font-weight:600">PROXY</span>'
        : '<span style="background:#334155;color:#e2e8f0;padding:2px 6px;border-radius:4px">' + (e.route_type||'') + '</span>';
      tr.innerHTML = '<td class="lt-time">' + ts + '</td><td>' + port + '</td><td>' + (e.client_ip||'') + '</td><td>' + domain + '</td><td>' + (e.method||'') +
        '</td><td>' + (e.status_code||'') + '</td><td>' + routeBadge + '</td><td class="lt-hits">1</td><td class="lt-latency">' + (e.latency_ms||0) + 'ms</td><td class="lt-bytes">' +
        formatBytes(bytes) + '</td><td class="lt-error" style="color:#f87171">' + (e.error||'') + '</td>';
      tbody.insertBefore(tr, tbody.firstChild);
      liveTrafficRows[key] = { tr, hits: 1, bytes, latency: e.latency_ms||0, ts, error: e.error||'' };
      while (tbody.children.length > 200) {
        const last = tbody.lastChild;
        // Clean up map entry for removed row.
        for (const k in liveTrafficRows) { if (liveTrafficRows[k].tr === last) { delete liveTrafficRows[k]; break; } }
        tbody.removeChild(last);
      }
    } catch(_) {}
  };
}

function wsSend(obj) {
  if (liveWS && liveWS.readyState === 1) liveWS.send(JSON.stringify(obj));
}

document.getElementById('wsConnectBtn').addEventListener('click', wsConnect);
document.getElementById('wsPauseBtn').addEventListener('click', () => wsSend({action:'pause'}));
document.getElementById('wsResumeBtn').addEventListener('click', () => wsSend({action:'resume'}));
document.getElementById('wsClearBtn').addEventListener('click', () => { document.getElementById('liveTrafficBody').innerHTML = ''; liveTrafficRows = {}; });
document.getElementById('wsFilterBtn').addEventListener('click', () => wsSend({action:'filter', filter: document.getElementById('wsFilter').value}));

// Ring buffer stats
async function refreshReportStats() {
  const r = await apiCall('GET', '/api/report/stats');
  if (!r.ok) return;
  document.getElementById('rbRows').textContent = r.data.current_rows || 0;
  document.getElementById('rbMax').textContent = r.data.max_rows || 0;
  document.getElementById('rbRAM').textContent = ((r.data.ram_bytes||0)/1024).toFixed(1);
  document.getElementById('rbNextClear').textContent = r.data.next_clear_in_sec || 0;
}

document.getElementById('clearBufferBtn').addEventListener('click', async () => {
  await apiCall('POST', '/api/report/clear');
  refreshReportStats();
});

// Report config
document.getElementById('saveReportCfgBtn').addEventListener('click', async () => {
  const body = {
    ring_buffer_max_rows: parseInt(document.getElementById('rptMaxRows').value, 10),
    auto_clear_seconds: parseInt(document.getElementById('rptClearSec').value, 10),
    auto_clear_enabled: document.getElementById('rptClearEnabled').checked,
  };
  const r = await apiCall('POST', '/api/report/config', body);
  if (!r.ok) { setMsg('rptCfgMsg', r.data.error || 'Failed', true); return; }
  setMsg('rptCfgMsg', 'Saved', false);
});

// Minute chart (simple canvas bar chart)
async function drawMinuteChart() {
  const r = await apiCall('GET', '/api/report/chart/minute?last=60');
  if (!r.ok) return;
  const canvas = document.getElementById('minuteChart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const pts = r.data || [];
  if (!pts.length) return;
  const maxBytes = Math.max(...pts.map(p => p.bytes), 1);
  const barW = Math.floor(canvas.width / pts.length) - 1;
  ctx.fillStyle = '#4f46e5';
  pts.forEach((p, i) => {
    const h = (p.bytes / maxBytes) * (canvas.height - 20);
    ctx.fillRect(i * (barW + 1), canvas.height - h - 10, barW, h);
  });
  ctx.fillStyle = '#8a8ab0';
  ctx.font = '10px monospace';
  if (pts.length > 0) ctx.fillText(pts[0].time, 2, canvas.height - 1);
  if (pts.length > 1) ctx.fillText(pts[pts.length-1].time, canvas.width - 100, canvas.height - 1);
}

// Top domains (report)
async function loadReportTopDomains() {
  const r = await apiCall('GET', '/api/report/top-domains?granularity=minute&top=10');
  if (!r.ok) return;
  const c = document.getElementById('reportTopDomains');
  const ranks = r.data || [];
  if (!ranks.length) { c.innerHTML = '<p style="color:#8a8ab0;font-size:13px">No data</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Domain</th><th>Bytes</th><th>Requests</th><th>Errors</th><th>Avg Latency</th></tr>';
  ranks.forEach(d => {
    html += '<tr><td>' + d.domain + '</td><td>' + formatBytes(d.total_bytes) + '</td><td>' + d.request_count +
      '</td><td>' + d.error_count + '</td><td>' + d.avg_latency_ms + 'ms</td></tr>';
  });
  html += '</table>';
  c.innerHTML = html;
}

// Disk usage
async function loadDiskUsage() {
  const r = await apiCall('GET', '/api/report/disk-usage');
  if (!r.ok) return;
  const c = document.getElementById('diskUsageInfo');
  c.innerHTML = '<b>Files:</b> ' + (r.data.total_files||0) + ' · <b>Size:</b> ' + formatBytes(r.data.total_bytes||0) +
    ' · <b>Oldest:</b> ' + (r.data.oldest_date||'-') + ' · <b>Newest:</b> ' + (r.data.newest_date||'-');
}

document.getElementById('exportCsvBtn').addEventListener('click', () => {
  const date = document.getElementById('csvDate').value;
  if (!date) return;
  window.open('/api/report/export-csv?date=' + date + '&token=' + authToken, '_blank');
});

// Alerts
async function loadAlerts() {
  const r = await apiCall('GET', '/api/report/alerts?limit=50');
  if (!r.ok) return;
  const c = document.getElementById('alertsList');
  const alerts = r.data || [];
  if (!alerts.length) { c.innerHTML = '<p style="color:#8a8ab0">No alerts</p>'; return; }
  let html = '';
  alerts.reverse().forEach(a => {
    const ts = new Date(a.timestamp).toLocaleString();
    const color = a.level === 'error' ? '#f87171' : '#fbbf24';
    html += '<div style="border-left:3px solid ' + color + ';padding:4px 8px;margin-bottom:4px">' +
      '<span style="color:' + color + '">[' + a.level + ']</span> ' + ts + ' — ' + a.message + '</div>';
  });
  c.innerHTML = html;
}

document.getElementById('clearAlertsBtn').addEventListener('click', async () => {
  await apiCall('POST', '/api/report/alerts/clear');
  loadAlerts();
});

// Tab-aware auto-refresh for report.
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (reportInterval) { clearInterval(reportInterval); reportInterval = null; }
    if (btn.dataset.tab === 'tab-report') {
      refreshReportStats();
      drawMinuteChart();
      loadReportTopDomains();
      loadDiskUsage();
      loadAlerts();
      reportInterval = setInterval(() => {
        refreshReportStats();
        drawMinuteChart();
        loadReportTopDomains();
      }, 5000);
    }
  });
});

// ── Phase 5 — Dashboard / Health ───────────────────────────
let dashInterval = null;

async function loadHealthStatus() {
  const r = await apiCall('GET', '/api/health/status');
  if (!r.ok) return;
  const groups = r.data.groups || [];
  let total = 0, alive = 0, slow = 0, dead = 0, totalLat = 0, latCount = 0;
  groups.forEach(g => {
    alive += g.alive || 0;
    slow += g.slow || 0;
    dead += g.dead || 0;
    (g.proxies || []).forEach(p => {
      total++;
      if (p.avg_latency > 0) { totalLat += p.avg_latency; latCount++; }
    });
  });
  document.getElementById('dbTotal').textContent = total;
  document.getElementById('dbAlive').textContent = alive;
  document.getElementById('dbSlow').textContent = slow;
  document.getElementById('dbDead').textContent = dead;
  document.getElementById('dbAvgLat').textContent = latCount ? Math.round(totalLat/latCount) + 'ms' : '—';

  const container = document.getElementById('healthGroupsContainer');
  if (!groups.length) { container.innerHTML = '<p style="color:#8a8ab0">No groups configured</p>'; return; }
  let html = '';
  groups.forEach(g => {
    html += '<div style="margin-bottom:16px">';
    html += '<h3 style="font-size:14px;color:#a78bfa;margin-bottom:6px">' + g.name + ' (' + g.alive + '/' + (g.proxies||[]).length + ' alive)</h3>';
    html += '<table class="mini-table"><tr><th>Host</th><th>Status</th><th>Latency</th><th>Avg</th><th>Success%</th><th>Weight</th><th>Conns</th><th>Ext IP</th></tr>';
    (g.proxies || []).forEach(p => {
      const dotClr = p.status === 'alive' ? '#4ade80' : p.status === 'slow' ? '#fbbf24' : p.status === 'dead' ? '#f87171' : '#8a8ab0';
      const pulse = p.status === 'alive' ? ' pulse' : '';
      html += '<tr><td>' + p.host + ':' + p.port + '</td>';
      html += '<td><span class="health-dot' + pulse + '" style="background:' + dotClr + '"></span>' + p.status + '</td>';
      html += '<td>' + (p.latency_ms||0) + 'ms</td>';
      html += '<td>' + (p.avg_latency||0) + 'ms</td>';
      html += '<td>' + ((p.success_rate||0)*100).toFixed(0) + '%</td>';
      html += '<td>' + (p.weight||0) + '</td>';
      html += '<td>' + (p.active_conns||0) + '</td>';
      html += '<td>' + (p.external_ip||'-') + '</td></tr>';
    });
    html += '</table></div>';
  });
  container.innerHTML = html;
}

document.getElementById('checkNowBtn').addEventListener('click', async () => {
  await apiCall('POST', '/api/health/check-now');
  setTimeout(loadHealthStatus, 2000);
});

// ── Groups ─────────────────────────────────────────────────
async function loadGroups() {
  const r = await apiCall('GET', '/api/groups');
  if (!r.ok) return;
  const groups = r.data.groups || [];
  const container = document.getElementById('groupsList');
  if (!groups.length) { container.innerHTML = '<p style="color:#8a8ab0">No groups yet</p>'; return; }
  let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">';
  groups.forEach(g => {
    html += '<div style="background:#0f1024;border:1px solid #0f3460;border-radius:8px;padding:12px">';
    html += '<div style="font-weight:600;color:#a78bfa;font-size:14px">' + g.name + '</div>';
    html += '<div style="font-size:12px;color:#8a8ab0;margin-top:4px">Mode: ' + g.rotation_mode + '</div>';
    html += '<div style="font-size:12px;color:#8a8ab0">Proxies: ' + g.alive_count + '/' + g.proxy_count + ' alive</div>';
    html += '<div style="font-size:12px;color:#8a8ab0">Ports: ' + (g.port_range||'none') + '</div>';
    html += '<div style="margin-top:8px"><button class="btn btn-xs" onclick="editGroup(\'' + g.name + '\')">Edit</button>';
    html += ' <button class="btn btn-xs" style="background:#dc2626;color:white" onclick="deleteGroup(\'' + g.name + '\')">Delete</button></div>';
    html += '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
  // Populate port-mapping group select.
  const sel = document.getElementById('pmGroup');
  if (sel) sel.innerHTML = groups.map(g => '<option value="' + g.name + '">' + g.name + '</option>').join('');
}

document.getElementById('newGroupBtn').addEventListener('click', async () => {
  const name = prompt('Group name:');
  if (!name) return;
  const mode = prompt('Rotation mode (roundrobin/random/sticky/leastconn/weighted):', 'roundrobin');
  const ptype = prompt('Proxy type (http/socks5):', 'http');
  const rawText = prompt('Proxy list (host:port per line):');
  if (rawText === null) return;
  const r = await apiCall('POST', '/api/groups', { name, rotation_mode: mode, proxy_type: ptype, raw_text: rawText });
  if (!r.ok) { alert(r.data.error || 'Failed'); return; }
  loadGroups();
});

async function editGroup(name) {
  const rawText = prompt('New proxy list for ' + name + ' (blank = keep):');
  const mode = prompt('Rotation mode (blank = keep):', '');
  const body = {};
  if (rawText) { body.raw_text = rawText; body.proxy_type = 'http'; }
  if (mode) body.rotation_mode = mode;
  if (Object.keys(body).length === 0) return;
  const r = await apiCall('PUT', '/api/groups/' + encodeURIComponent(name), body);
  if (!r.ok) { alert(r.data.error || 'Failed'); return; }
  loadGroups();
}

async function deleteGroup(name) {
  if (!confirm('Delete group "' + name + '"?')) return;
  const r = await apiCall('DELETE', '/api/groups/' + encodeURIComponent(name));
  if (!r.ok) { alert(r.data.error || 'Failed'); return; }
  loadGroups();
}

// ── Port Mappings ──────────────────────────────────────────
let portMappings = [];

async function loadPortMappings() {
  const r = await apiCall('GET', '/api/port-mappings');
  if (!r.ok) return;
  portMappings = r.data.mappings || [];
  renderPMTable();
}

function renderPMTable() {
  const c = document.getElementById('portMapTable');
  if (!portMappings.length) { c.innerHTML = '<p style="color:#8a8ab0">No mappings</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Start</th><th>End</th><th>Group</th><th></th></tr>';
  portMappings.forEach((m, i) => {
    html += '<tr><td>' + m.port_start + '</td><td>' + m.port_end + '</td><td>' + m.group_name + '</td>';
    html += '<td><button class="btn btn-xs" style="background:#dc2626;color:white" onclick="removePM(' + i + ')">X</button></td></tr>';
  });
  html += '</table>';
  c.innerHTML = html;
}

function removePM(idx) { portMappings.splice(idx, 1); renderPMTable(); }

document.getElementById('addPMBtn').addEventListener('click', () => {
  const ps = parseInt(document.getElementById('pmStart').value, 10);
  const pe = parseInt(document.getElementById('pmEnd').value, 10);
  const grp = document.getElementById('pmGroup').value;
  if (!ps || !pe || !grp) { setMsg('pmMsg', 'Missing fields', true); return; }
  if (pe < ps) { setMsg('pmMsg', 'end < start', true); return; }
  // Overlap check.
  for (const m of portMappings) {
    if (!(pe < m.port_start || ps > m.port_end)) {
      setMsg('pmMsg', 'Overlap with ' + m.group_name, true);
      return;
    }
  }
  portMappings.push({ port_start: ps, port_end: pe, group_name: grp });
  renderPMTable();
  setMsg('pmMsg', 'Added', false);
});

document.getElementById('savePMBtn').addEventListener('click', async () => {
  const r = await apiCall('POST', '/api/port-mappings', { mappings: portMappings });
  if (!r.ok) { setMsg('pmMsg', r.data.error || 'Failed', true); return; }
  setMsg('pmMsg', 'Saved — restart required', false);
});

// ── Import Sources ─────────────────────────────────────────
async function loadImportSources() {
  const r = await apiCall('GET', '/api/import/sources');
  if (!r.ok) return;
  const sources = r.data.sources || [];
  const c = document.getElementById('importSourcesList');
  if (!sources.length) { c.innerHTML = '<p style="color:#8a8ab0">No sources</p>'; return; }
  let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">';
  sources.forEach(s => {
    html += '<div style="background:#0f1024;border:1px solid #0f3460;border-radius:8px;padding:12px">';
    html += '<div style="font-weight:600;color:#a78bfa">' + s.name + '</div>';
    html += '<div style="font-size:11px;color:#8a8ab0;word-break:break-all">' + s.url + '</div>';
    html += '<div style="font-size:12px;color:#8a8ab0;margin-top:4px">Group: ' + s.group_name + ' · ' + s.proxy_type + '</div>';
    html += '<div style="font-size:12px;color:#8a8ab0">Interval: ' + s.interval_sec + 's · Last: ' + (s.last_count||0) + ' proxies</div>';
    html += '<div style="margin-top:8px">';
    html += '<button class="btn btn-xs" onclick="fetchImportNow(\'' + s.name + '\')">Fetch Now</button>';
    html += ' <button class="btn btn-xs" style="background:#dc2626;color:white" onclick="deleteImport(\'' + s.name + '\')">Delete</button>';
    html += '</div></div>';
  });
  html += '</div>';
  c.innerHTML = html;
}

document.getElementById('newImportBtn').addEventListener('click', async () => {
  const name = prompt('Source name:');
  if (!name) return;
  const url = prompt('URL:');
  if (!url) return;
  const groupName = prompt('Target group name:');
  if (!groupName) return;
  const proxyType = prompt('Proxy type (http/socks5):', 'http');
  const intervalSec = parseInt(prompt('Interval (sec):', '300'), 10) || 300;
  const r = await apiCall('POST', '/api/import/sources', { name, url, group_name: groupName, proxy_type: proxyType, interval_sec: intervalSec, enabled: true });
  if (!r.ok) { alert(r.data.error || 'Failed'); return; }
  loadImportSources();
});

async function fetchImportNow(name) {
  const r = await apiCall('POST', '/api/import/fetch-now/' + encodeURIComponent(name));
  if (!r.ok) { alert(r.data.error || 'Failed'); return; }
  alert('Fetched ' + (r.data.fetched||0) + ' proxies');
  loadImportSources();
}

async function deleteImport(name) {
  if (!confirm('Delete source "' + name + '"?')) return;
  await apiCall('DELETE', '/api/import/sources/' + encodeURIComponent(name));
  loadImportSources();
}

// ── Health Config + Retry ──────────────────────────────────
async function loadHealthConfig() {
  const r = await apiCall('GET', '/api/health/config');
  if (!r.ok) return;
  document.getElementById('hcEnabled').checked = r.data.enabled;
  document.getElementById('hcInterval').value = r.data.interval_sec || 30;
  document.getElementById('hcTimeout').value = r.data.timeout_sec || 5;
  document.getElementById('hcSlow').value = r.data.slow_threshold_ms || 3000;
  document.getElementById('hcConcurrent').value = r.data.max_concurrent || 20;
  document.getElementById('hcTestURL').value = r.data.test_url || 'http://httpbin.org/ip';
}

document.getElementById('saveHCBtn').addEventListener('click', async () => {
  const body = {
    enabled: document.getElementById('hcEnabled').checked,
    interval_sec: parseInt(document.getElementById('hcInterval').value, 10),
    timeout_sec: parseInt(document.getElementById('hcTimeout').value, 10),
    slow_threshold_ms: parseInt(document.getElementById('hcSlow').value, 10),
    max_concurrent: parseInt(document.getElementById('hcConcurrent').value, 10),
    test_url: document.getElementById('hcTestURL').value,
  };
  const r = await apiCall('POST', '/api/health/config', body);
  setMsg('hcMsg', r.ok ? 'Saved' : (r.data.error||'Failed'), !r.ok);
});

async function loadRetryConfig() {
  const r = await apiCall('GET', '/api/config/retry');
  if (!r.ok) return;
  document.getElementById('retryEnabled').checked = r.data.enabled;
  document.getElementById('retryMax').value = r.data.max_attempts || 3;
  document.getElementById('retryBackoff').value = r.data.backoff_ms || 100;
}

document.getElementById('saveRetryBtn').addEventListener('click', async () => {
  const body = {
    enabled: document.getElementById('retryEnabled').checked,
    max_attempts: parseInt(document.getElementById('retryMax').value, 10),
    backoff_ms: parseInt(document.getElementById('retryBackoff').value, 10),
  };
  const r = await apiCall('POST', '/api/config/retry', body);
  setMsg('retryMsg', r.ok ? 'Saved' : (r.data.error||'Failed'), !r.ok);
});

// Tab-aware refresh.
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (dashInterval) { clearInterval(dashInterval); dashInterval = null; }
    if (btn.dataset.tab === 'tab-dashboard') {
      loadHealthStatus();
      dashInterval = setInterval(loadHealthStatus, 10000);
    } else if (btn.dataset.tab === 'tab-groups') {
      loadGroups();
      loadImportSources();
      loadHealthConfig();
      loadRetryConfig();
    } else if (btn.dataset.tab === 'tab-portmap') {
      loadGroups().then(loadPortMappings);
    }
  });
});

// ── Init ───────────────────────────────────────────────────
async function initAll() {
  await loadConfig();
  loadWhitelist();
  loadAutoBypass();
  refreshAbpStats();
  loadForceProxy();
  loadBudgetConfig();
  loadHealthStatus();
  dashInterval = setInterval(loadHealthStatus, 10000);
}
// ============ Phase 6 ============
async function apiGet(path){
  const r = await apiCall('GET', path);
  if(!r.ok) throw new Error((r.data&&r.data.error)||'failed');
  return r.data;
}
async function apiPost(path, body){
  const r = await apiCall('POST', path, body||{});
  if(!r.ok) throw new Error((r.data&&r.data.error)||'failed');
  return r.data;
}
function applyRolePermissions(){
  const role = sessionStorage.getItem('pd_role') || 'admin';
  const isAdmin = role === 'admin';
  const isWriter = isAdmin || role === 'operator';
  document.querySelectorAll('.admin-only').forEach(el=>{ el.style.display = isAdmin ? '' : 'none'; });
  document.querySelectorAll('.write-only').forEach(el=>{ if(!isWriter) el.style.display = 'none'; });
}

// My Account
async function loadMyAccount(){
  try{
    const data = await apiGet('/api/me');
    const box = document.getElementById('totpStatus');
    if(data.totp_enabled){
      box.textContent = '2FA đã bật ✓';
      document.getElementById('enableTOTPBtn').style.display='none';
      document.getElementById('disableTOTPBtn').style.display='';
    } else {
      box.textContent = '2FA chưa bật';
      document.getElementById('enableTOTPBtn').style.display='';
      document.getElementById('disableTOTPBtn').style.display='none';
    }
  }catch(e){}
}
document.getElementById('changePwBtn')?.addEventListener('click', async ()=>{
  const oldP = document.getElementById('oldPassword').value;
  const newP = document.getElementById('newPassword').value;
  try{
    await apiPost('/api/me/change-password', {old_password: oldP, new_password: newP});
    document.getElementById('pwMsg').textContent = 'Đã đổi mật khẩu';
    document.getElementById('oldPassword').value=''; document.getElementById('newPassword').value='';
  }catch(e){ document.getElementById('pwMsg').textContent = e.message; }
});

let totpSessionToken = '';
document.getElementById('enableTOTPBtn')?.addEventListener('click', async ()=>{
  const data = await apiPost('/api/me/totp/setup', {});
  totpSessionToken = data.session_token;
  document.getElementById('totpSetupBox').style.display='';
  document.getElementById('totpSecretText').textContent = 'Secret: ' + data.secret;
  const qrSrc = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(data.qr_url);
  document.getElementById('totpQR').src = qrSrc;
  const inputs = document.querySelectorAll('#totpConfirmInputs .totp-digit');
  inputs.forEach((inp, idx)=>{
    inp.oninput = ()=>{
      inp.value = inp.value.replace(/\D/g,'');
      if(inp.value && idx < inputs.length-1) inputs[idx+1].focus();
    };
    inp.onkeydown = (e)=>{ if(e.key==='Backspace' && !inp.value && idx>0) inputs[idx-1].focus(); };
  });
});
document.getElementById('confirmTOTPBtn')?.addEventListener('click', async ()=>{
  const code = Array.from(document.querySelectorAll('#totpConfirmInputs .totp-digit')).map(i=>i.value).join('');
  try{
    const data = await apiPost('/api/me/totp/confirm', {session_token: totpSessionToken, code: code});
    alert('2FA đã bật. Recovery codes (lưu lại NGAY):\n\n' + data.recovery_codes.join('\n'));
    document.getElementById('totpSetupBox').style.display='none';
    loadMyAccount();
  }catch(e){ document.getElementById('totpMsg').textContent = e.message; }
});
document.getElementById('disableTOTPBtn')?.addEventListener('click', async ()=>{
  const pw = prompt('Nhập mật khẩu để tắt 2FA:');
  if(!pw) return;
  try{ await apiPost('/api/me/totp/disable', {password: pw}); loadMyAccount(); }
  catch(e){ document.getElementById('totpMsg').textContent = e.message; }
});

// Users
async function loadUsers(){
  try{
    const data = await apiGet('/api/users');
    const tbody = document.querySelector('#usersTable tbody');
    tbody.innerHTML = '';
    (data.users||[]).forEach(u=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${u.username}</td><td>${u.role}</td>
        <td>${u.totp_enabled?'✓':'—'}</td>
        <td>${u.disabled?'Disabled':'Active'}</td>
        <td>${u.last_login?new Date(u.last_login*1000).toLocaleString():'—'}</td>
        <td><button class="btn btn-sm" data-edit="${u.id}">Edit</button>
            <button class="btn btn-sm btn-danger" data-del="${u.id}">Del</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editUser(b.dataset.edit));
    tbody.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>deleteUser(b.dataset.del));
  }catch(e){}
}
document.getElementById('newUserBtn')?.addEventListener('click', async ()=>{
  const username = prompt('Username:'); if(!username) return;
  const password = prompt('Password (>= 8 ký tự):'); if(!password) return;
  const role = prompt('Role (admin/operator/viewer):', 'viewer'); if(!role) return;
  try{ await apiPost('/api/users', {username, password, role}); loadUsers(); }
  catch(e){ alert(e.message); }
});
async function editUser(id){
  const action = prompt('1=reset pw, 2=change role, 3=toggle disabled', '1');
  if(action==='1'){
    const p = prompt('New password:'); if(!p) return;
    await apiPut('/api/users/'+id, {password: p});
  } else if(action==='2'){
    const r = prompt('New role (admin/operator/viewer):'); if(!r) return;
    await apiPut('/api/users/'+id, {role: r});
  } else if(action==='3'){
    const d = confirm('Disable user? (Cancel = enable)');
    await apiPut('/api/users/'+id, {disabled: d});
  }
  loadUsers();
}
async function deleteUser(id){
  if(!confirm('Xóa user này?')) return;
  try{ await apiDelete('/api/users/'+id); loadUsers(); }
  catch(e){ alert(e.message); }
}

// API Tokens
async function loadTokens(){
  try{
    const data = await apiGet('/api/tokens');
    const tbody = document.querySelector('#tokensTable tbody');
    tbody.innerHTML = '';
    (data.tokens||[]).forEach(t=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${t.name}</td><td>${(t.permissions||[]).join(', ')}</td>
        <td>${t.created_at?new Date(t.created_at*1000).toLocaleDateString():'—'}</td>
        <td>${t.expires_at?new Date(t.expires_at*1000).toLocaleDateString():'never'}</td>
        <td>${t.last_used?new Date(t.last_used*1000).toLocaleString():'—'}</td>
        <td><button class="btn btn-sm btn-danger" data-rev="${t.id}">${t.disabled?'Revoked':'Revoke'}</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('[data-rev]').forEach(b=>b.onclick=()=>revokeToken(b.dataset.rev));
  }catch(e){}
}
document.getElementById('newTokenBtn')?.addEventListener('click', async ()=>{
  const name = prompt('Token name:'); if(!name) return;
  const perms = prompt('Permissions (comma-separated, e.g. read:*,write:config):', 'read:*');
  if(!perms) return;
  const expDays = prompt('Expires in N days (0 = never):', '0');
  const exp = parseInt(expDays,10)>0 ? Math.floor(Date.now()/1000)+parseInt(expDays,10)*86400 : 0;
  try{
    const data = await apiPost('/api/tokens', {name, permissions: perms.split(',').map(s=>s.trim()), expires_at: exp});
    const modal = `Token (hiện 1 LẦN DUY NHẤT — COPY NGAY):\n\n${data.token}`;
    prompt(modal, data.token);
    loadTokens();
  }catch(e){ alert(e.message); }
});
async function revokeToken(id){
  if(!confirm('Revoke token?')) return;
  await apiDelete('/api/tokens/'+id);
  loadTokens();
}

// Sync
async function loadSyncStatus(){
  try{
    const data = await apiGet('/api/sync/status');
    document.getElementById('syncRole').value = data.role || 'standalone';
    updateSyncBoxes();
    if(data.slaves){
      const tbody = document.querySelector('#slavesTable tbody');
      tbody.innerHTML = '';
      data.slaves.forEach(s=>{
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.name}</td><td>${s.url}</td><td>${s.enabled?'✓':'—'}</td>
          <td>${s.last_sync?new Date(s.last_sync*1000).toLocaleString():'—'}</td>
          <td>${s.status||'—'}</td><td>${s.last_error||''}</td>`;
        tbody.appendChild(tr);
      });
    }
    if(data.last_receive){
      document.getElementById('slaveLastReceive').textContent =
        'Last receive: ' + new Date(data.last_receive*1000).toLocaleString();
    }
  }catch(e){}
}
function updateSyncBoxes(){
  const role = document.getElementById('syncRole').value;
  document.getElementById('masterBox').style.display = role==='master'?'':'none';
  document.getElementById('slaveBox').style.display = role==='slave'?'':'none';
}
document.getElementById('syncRole')?.addEventListener('change', updateSyncBoxes);
document.getElementById('copySecretBtn')?.addEventListener('click', ()=>{
  const s = document.getElementById('syncSecret').value;
  navigator.clipboard.writeText(s); alert('Copied');
});
document.getElementById('syncNowBtn')?.addEventListener('click', async ()=>{
  try{ const r = await apiPost('/api/sync/push', {}); alert(JSON.stringify(r.results,null,2)); }
  catch(e){ alert(e.message); }
});

// DNS
async function loadDNS(){
  try{
    const data = await apiGet('/api/system/dns');
    document.getElementById('dnsServers').value = (data.dns_servers||[]).join('\n');
    document.getElementById('dohEnabled').checked = !!data.dns_over_https;
  }catch(e){}
}
document.getElementById('saveDnsBtn')?.addEventListener('click', async ()=>{
  const servers = document.getElementById('dnsServers').value.split('\n').map(s=>s.trim()).filter(Boolean);
  const doh = document.getElementById('dohEnabled').checked;
  await apiPost('/api/system/dns', {dns_servers: servers, dns_over_https: doh, timezone: 'UTC'});
  alert('DNS saved');
});
document.getElementById('dnsTestBtn')?.addEventListener('click', async ()=>{
  const d = document.getElementById('dnsTestDomain').value.trim();
  if(!d) return;
  const r = await apiPost('/api/system/dns/test', {domain: d});
  document.getElementById('dnsTestResult').textContent = JSON.stringify(r,null,2);
});

// Backups
async function loadBackups(){
  try{
    const data = await apiGet('/api/system/backups');
    const tbody = document.querySelector('#backupsTable tbody');
    tbody.innerHTML = '';
    (data.backups||[]).forEach(b=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${b.filename}</td><td>${(b.size/1024).toFixed(1)} KB</td>
        <td>${new Date(b.created_at).toLocaleString()}</td>
        <td><button class="btn btn-sm" data-restore="${b.filename}">Restore</button>
            <button class="btn btn-sm btn-danger" data-delbk="${b.filename}">Del</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('[data-restore]').forEach(b=>b.onclick=async()=>{
      if(!confirm('Restore '+b.dataset.restore+'? Cấu hình hiện tại sẽ bị ghi đè.')) return;
      try{ await apiPost('/api/system/backups/restore', {filename: b.dataset.restore}); alert('Restored'); location.reload(); }
      catch(e){ alert(e.message); }
    });
    tbody.querySelectorAll('[data-delbk]').forEach(b=>b.onclick=async()=>{
      if(!confirm('Xóa backup?')) return;
      await apiDelete('/api/system/backups/'+encodeURIComponent(b.dataset.delbk));
      loadBackups();
    });
  }catch(e){}
}
document.getElementById('createBackupBtn')?.addEventListener('click', async ()=>{
  await apiPost('/api/system/backups', {}); loadBackups();
});
document.getElementById('exportConfigBtn')?.addEventListener('click', ()=>{
  const t = sessionStorage.getItem('pd_token');
  window.open('/api/system/export?token='+encodeURIComponent(t), '_blank');
});
document.getElementById('importConfigBtn')?.addEventListener('click', async ()=>{
  const f = document.getElementById('importConfigFile').files[0];
  if(!f){ alert('Chọn file'); return; }
  const fd = new FormData(); fd.append('file', f);
  const t = sessionStorage.getItem('pd_token');
  const res = await fetch('/api/system/import',{method:'POST', headers:{'Authorization':'Bearer '+t}, body: fd});
  const data = await res.json();
  if(res.ok) alert('Imported'); else alert(data.error||'failed');
});

// System Info
async function loadSystemInfo(){
  try{
    const d = await apiGet('/api/system/info');
    const ramPct = d.total_ram>0 ? Math.round((1-d.free_ram/d.total_ram)*100) : 0;
    const diskPct = d.disk_total>0 ? Math.round((1-d.disk_free/d.disk_total)*100) : 0;
    const fmt = b => (b/(1024*1024*1024)).toFixed(2)+' GB';
    const up = d.uptime_sec; const h = Math.floor(up/3600), m = Math.floor((up%3600)/60);
    document.getElementById('systemInfoBox').innerHTML = `
      <div>Host: ${d.hostname}</div>
      <div>OS: ${d.os}/${d.arch} · ${d.cpu_cores} cores · ${d.go_version}</div>
      <div>RAM: ${fmt(d.total_ram-d.free_ram)} / ${fmt(d.total_ram)} (${ramPct}%)</div>
      <div>Disk: ${fmt(d.disk_total-d.disk_free)} / ${fmt(d.disk_total)} (${diskPct}%)</div>
      <div>Uptime: ${h}h ${m}m · Goroutines: ${d.goroutine_count}</div>
      <div>Load: ${d.load_avg.map(x=>x.toFixed(2)).join(' ')}</div>
      <div>Version: ${d.version} · PID: ${d.pid}</div>`;
  }catch(e){}
}

// Helper methods
async function apiPut(path, body){
  const r = await apiCall('PUT', path, body||{});
  if(!r.ok) throw new Error((r.data&&r.data.error)||'failed');
  return r.data;
}
async function apiDelete(path){
  const r = await apiCall('DELETE', path);
  if(!r.ok) throw new Error((r.data&&r.data.error)||'failed');
  return r.data;
}

// Tab loaders
const phase6TabLoaders = {
  'tab-account': loadMyAccount,
  'tab-users': ()=>{ loadUsers(); loadTokens(); },
  'tab-settings': ()=>{ loadSyncStatus(); loadDNS(); loadBackups(); loadSystemInfo(); },
};
document.querySelectorAll('.tab-btn').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    const id = btn.dataset.tab;
    if(phase6TabLoaders[id]) phase6TabLoaders[id]();
  });
});
// Auto-refresh system info on settings tab every 10s.
setInterval(()=>{
  if(document.getElementById('tab-settings')?.style.display !== 'none') loadSystemInfo();
}, 10000);

document.addEventListener('DOMContentLoaded', ()=>{ applyRolePermissions(); });
document.addEventListener('DOMContentLoaded', initAll);
