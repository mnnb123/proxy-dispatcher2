let authToken = sessionStorage.getItem('pd_token');
if (!authToken) window.location.href = 'login.html';

// ── Dark Mode ─────────────────────────────────────────────
(function initTheme() {
  const saved = localStorage.getItem('pd_theme');
  if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();

function toggleTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const next = isDark ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('pd_theme', next);
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = next === 'dark' ? '\u263E' : '\u2600';
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? '\u263E' : '\u2600';
    btn.addEventListener('click', toggleTheme);
  }
});

// ── Toast Notifications ───────────────────────────────────
const Toast = {
  _icons: { success: '\u2713', error: '\u2717', warning: '\u26A0', info: '\u2139' },
  show(type, title, message, duration) {
    duration = duration || 4000;
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.innerHTML =
      '<span class="toast-icon">' + (this._icons[type] || '') + '</span>' +
      '<div class="toast-body">' +
        '<div class="toast-title">' + title + '</div>' +
        (message ? '<div class="toast-message">' + message + '</div>' : '') +
      '</div>' +
      '<button class="toast-close" aria-label="Close">\u00D7</button>';
    el.querySelector('.toast-close').addEventListener('click', () => this._remove(el));
    container.appendChild(el);
    setTimeout(() => this._remove(el), duration);
  },
  _remove(el) {
    if (!el || !el.parentNode) return;
    el.classList.add('removing');
    setTimeout(() => el.remove(), 200);
  },
  success(title, msg) { this.show('success', title, msg); },
  error(title, msg) { this.show('error', title, msg, 6000); },
  warning(title, msg) { this.show('warning', title, msg, 5000); },
  info(title, msg) { this.show('info', title, msg); }
};

// ── Reset Ports ───────────────────────────────────────────
document.getElementById('resetPortsBtn')?.addEventListener('click', async () => {
  if (!confirm('Reset toàn bộ ports?\nListeners sẽ khởi động lại + reload proxy map + re-check health.\nKết nối đang mở không bị ngắt.')) return;
  const btn = document.getElementById('resetPortsBtn');
  btn.disabled = true;
  btn.textContent = 'Đang reset...';
  try {
    const r = await apiCall('POST', '/api/system/reset-ports');
    if (r.ok) {
      Toast.success('Reset Ports', 'Đã reset — ' + r.data.active_ports + ' ports đang hoạt động');
      loadConfig();          // refresh status badge
      loadHealthStatus?.();  // refresh health dashboard
    } else {
      Toast.error('Reset Ports', r.data.error || 'Reset thất bại');
    }
  } catch (e) {
    Toast.error('Reset Ports', e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#8635; Reset Ports';
  }
});

// ── Sidebar Navigation ───────────────────────────────────
function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const hamburger = document.getElementById('hamburgerBtn');

  // Hamburger toggle
  if (hamburger) {
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('active');
    });
  }
  // Close on overlay click
  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
    });
  }

  // Nav item clicks → switch tabs + tab-aware data refresh
  document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
      item.classList.add('active');
      const tab = document.getElementById(item.dataset.tab);
      if (tab) tab.style.display = 'block';
      // Close sidebar on mobile
      sidebar.classList.remove('open');
      if (overlay) overlay.classList.remove('active');

      // Clear existing intervals
      if (typeof bwInterval !== 'undefined' && bwInterval) { clearInterval(bwInterval); bwInterval = null; }
      if (typeof dashInterval !== 'undefined' && dashInterval) { clearInterval(dashInterval); dashInterval = null; }
      if (typeof reportInterval !== 'undefined' && reportInterval) { clearInterval(reportInterval); reportInterval = null; }

      // Tab-specific data loading
      const t = item.dataset.tab;
      if (t === 'tab-bandwidth') {
        refreshBandwidth();
        bwInterval = setInterval(refreshBandwidth, 5000);
      } else if (t === 'tab-dashboard') {
        loadHealthStatus();
        dashInterval = setInterval(loadHealthStatus, 10000);
      } else if (t === 'tab-groups') {
        loadGroups(); loadImportSources(); loadHealthConfig(); loadRetryConfig();
      } else if (t === 'tab-session') {
        loadSessionTab();
      } else if (t === 'tab-portmap') {
        loadGroups().then(loadPortMappings);
      } else if (t === 'tab-report') {
        if (typeof refreshReportStats === 'function') refreshReportStats();
        if (typeof drawMinuteChart === 'function') drawMinuteChart();
        if (typeof loadReportTopDomains === 'function') loadReportTopDomains();
        if (typeof loadDiskUsage === 'function') loadDiskUsage();
        if (typeof loadAlerts === 'function') loadAlerts();
        reportInterval = setInterval(() => {
          if (typeof refreshReportStats === 'function') refreshReportStats();
          if (typeof drawMinuteChart === 'function') drawMinuteChart();
          if (typeof loadReportTopDomains === 'function') loadReportTopDomains();
        }, 5000);
      }
      // Phase 6 tabs
      if (typeof phase6TabLoaders !== 'undefined' && phase6TabLoaders[t]) {
        phase6TabLoaders[t]();
      }
    });
  });
}

// ── Skeleton helpers ──────────────────────────────────────
function hideSkeleton(skeletonId, dataId) {
  const sk = document.getElementById(skeletonId);
  const dt = document.getElementById(dataId);
  if (sk) sk.style.display = 'none';
  if (dt) dt.style.display = '';
}

// ── Staggered animation ──────────────────────────────────
function animateList(container) {
  const items = container.querySelectorAll('tr, .stat-card, .card');
  items.forEach((el, i) => {
    el.classList.add('animate-in');
    el.style.animationDelay = (i * 30) + 'ms';
  });
}

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
  if (!el) return;
  el.textContent = text;
  el.className = 'msg ' + (isError ? 'err' : 'ok');
  // Also show toast for important messages
  if (isError && text) Toast.error('Error', text);
  else if (!isError && text) Toast.success('Success', text);
}

// Legacy .tab-btn switching removed — sidebar handles all tab switching now.

// Initialize sidebar
initSidebar();

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
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center" class="text-muted">Chua co proxy nao. Nhap proxy vao o tren va nhan Save & Apply.</td></tr>';
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

function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch(e) { return Promise.reject(e); }
  finally { ta.remove(); }
  return Promise.resolve();
}

document.getElementById('copyBtn').addEventListener('click', async () => {
  const inp = await apiCall('GET', '/api/config/input');
  if (!inp.ok || !inp.data.mapping || inp.data.mapping.length === 0) {
    setMsg('inputMsg', 'Khong co output de copy', true);
    return;
  }
  const text = inp.data.mapping.map(m => m.output_addr).join('\n');
  copyToClipboard(text).then(
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

  loadBannedIPs();
  loadOutputAccounts();
}

// ── Output accounts (user/pass on output ports) ────────────
async function loadOutputAccounts() {
  const r = await apiCall('GET', '/api/config/whitelist/accounts');
  const c = document.getElementById('oaTable');
  if (!r.ok) { c.innerHTML = ''; return; }
  const list = r.data.accounts || [];
  const warn = document.getElementById('oaWarn');
  if (list.length && !r.data.whitelist_enabled) {
    setMsg('oaWarn', 'Whitelist đang tắt nên cổng output đang mở cho mọi IP, chưa yêu cầu user/pass. Bật "Enable Whitelist" để áp dụng.', true);
  } else { warn.textContent = ''; warn.className = 'msg'; }
  if (!list.length) { c.innerHTML = '<p class="text-muted">Chưa có tài khoản nào.</p>'; return; }
  let html = '<table class="data-table"><thead><tr><th>User</th><th>Pass</th><th>Ghi chú</th><th></th></tr></thead><tbody>';
  list.forEach((a, i) => {
    html += '<tr><td>' + escH(a.user) + '</td><td>' + escH(a.pass) + '</td><td>' + escH(a.note || '') + '</td>' +
      '<td><button class="btn btn-xs" data-oa-copy="' + i + '">Copy</button> ' +
      '<button class="btn btn-xs btn-danger" data-oa-del="' + i + '">X</button></td></tr>';
  });
  c.innerHTML = html + '</tbody></table>';
  c.querySelectorAll('[data-oa-copy]').forEach(b => b.addEventListener('click', () => {
    const a = list[+b.dataset.oaCopy];
    copyToClipboard(a.user + ':' + a.pass);
    setMsg('oaMsg', 'Đã copy ' + a.user + ':…', false);
  }));
  c.querySelectorAll('[data-oa-del]').forEach(b => b.addEventListener('click', async () => {
    const a = list[+b.dataset.oaDel];
    if (!confirm('Xóa tài khoản "' + a.user + '"? Client đang dùng tài khoản này sẽ không kết nối mới được.')) return;
    const d = await apiCall('DELETE', '/api/config/whitelist/accounts', { user: a.user });
    if (!d.ok) { setMsg('oaMsg', d.data.error || 'Failed', true); return; }
    setMsg('oaMsg', 'Đã xóa ' + a.user, false);
    loadOutputAccounts();
  }));
}

document.getElementById('oaSaveBtn').addEventListener('click', async () => {
  const body = {
    user: document.getElementById('oaUser').value.trim(),
    pass: document.getElementById('oaPass').value,
    note: document.getElementById('oaNote').value,
  };
  if (!body.user) { setMsg('oaMsg', 'Nhập user', true); return; }
  const r = await apiCall('POST', '/api/config/whitelist/accounts', body);
  if (!r.ok) { setMsg('oaMsg', r.data.error || 'Failed', true); return; }
  setMsg('oaMsg', 'Đã lưu: ' + r.data.account.user + ':' + r.data.account.pass, false);
  ['oaUser', 'oaPass', 'oaNote'].forEach(id => { document.getElementById(id).value = ''; });
  loadOutputAccounts();
});

async function loadBannedIPs() {
  const banned = await apiCall('GET', '/api/config/whitelist/banned');
  if (banned.ok) {
    const ips = banned.data.ips || [];
    document.getElementById('bannedList').textContent = ips.length ? ips.join(', ') : 'None';
    document.getElementById('clearBannedBtn').style.display = ips.length ? '' : 'none';
  }
}

document.getElementById('banIpBtn').addEventListener('click', async () => {
  const ip = document.getElementById('banIpInput').value.trim();
  if (!ip) { setMsg('wlConfigMsg', 'Nhập IP cần ban', true); return; }
  const r = await apiCall('POST', '/api/config/whitelist/ban', { ip });
  if (!r.ok) { setMsg('wlConfigMsg', r.data.error || 'Failed', true); return; }
  setMsg('wlConfigMsg', 'Đã ban ' + ip, false);
  document.getElementById('banIpInput').value = '';
  loadBannedIPs();
});

document.getElementById('clearBannedBtn').addEventListener('click', async () => {
  const r = await apiCall('DELETE', '/api/config/whitelist/banned');
  if (!r.ok) { setMsg('wlConfigMsg', r.data.error || 'Failed', true); return; }
  setMsg('wlConfigMsg', 'Đã xóa ' + (r.data.cleared ?? 0) + ' IP bị ban', false);
  loadBannedIPs();
});

function renderWhitelistTable(entries) {
  const c = document.getElementById('wlTable');
  if (!entries.length) { c.innerHTML = '<p style="color:var(--text-muted);font-size:13px">No entries</p>'; return; }
  let html = '<table class="mini-table"><tr><th>IP</th><th>Type</th><th>Note</th><th>Expires</th><th></th></tr>';
  entries.forEach(e => {
    const exp = e.expires_at ? new Date(e.expires_at * 1000).toLocaleString() : 'Never';
    html += '<tr><td>' + e.ip + '</td><td>' + (e.type||'single') + '</td><td>' + (e.note||'') + '</td><td>' + exp + '</td>';
    html += '<td><button class="btn btn-xs" class="btn-danger" onclick="removeWhitelistIP(\'' + e.ip + '\')">X</button></td></tr>';
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

async function saveWhitelistConfig() {
  const body = {
    enabled: document.getElementById('wlEnabled').checked,
    entries: [],
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
}

document.getElementById('saveWlConfigBtn').addEventListener('click', saveWhitelistConfig);

// Auto-save when Enable Whitelist checkbox is toggled.
document.getElementById('wlEnabled').addEventListener('change', async () => {
  await saveWhitelistConfig();
  loadOutputAccounts();
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
    tr.style.color = 'var(--color-success)';
    const ts = new Date(ev.time).toLocaleTimeString();
    tr.innerHTML = '<td>' + ts + '</td><td>' + (ev.port||'') + '</td><td style="font-weight:600">' + ev.domain +
      '</td><td>' + formatBytes(ev.size) + '</td><td>' + formatBytes(ev.threshold) +
      '</td><td><span style="background:var(--color-success-light);color:var(--color-success);padding:2px 8px;border-radius:4px;font-weight:600">BYPASSED</span></td>' +
      '<td><button class="btn btn-sm" style="background:var(--color-warning);color:var(--text-inverse);padding:2px 6px;font-size:11px" onclick="addToForceProxy(\'' +
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

  let html = '<circle cx="18" cy="18" r="15.915" fill="none" stroke="var(--bg-inset)" stroke-width="3.8"></circle>';
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
  if (!domains.length) { c.innerHTML = '<p style="color:var(--text-muted);font-size:13px">No data yet</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Domain</th><th>Route</th><th>Bytes</th><th>Requests</th><th>Avg Size</th></tr>';
  domains.forEach(d => {
    const rt = d.route_type || 'proxy';
    const color = rt === 'direct' ? 'var(--color-success)' : rt === 'mixed' ? 'var(--color-warning)' : 'var(--color-accent)';
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

// Tab-aware auto-refresh for bandwidth is handled in initSidebar().

// ── Report Tab ─────────────────────────────────────────────
let liveWS = null;
let liveTrafficRows = {};
let reportInterval = null;

function wsConnect() {
  if (liveWS && liveWS.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  liveWS = new WebSocket(proto + '//' + location.host + '/ws/live-traffic?token=' + authToken);
  liveWS.onopen = () => { document.getElementById('wsStatus').textContent = 'connected'; document.getElementById('wsStatus').style.color = 'var(--color-success)'; };
  liveWS.onclose = () => { document.getElementById('wsStatus').textContent = 'disconnected'; document.getElementById('wsStatus').style.color = 'var(--color-danger)'; };
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
      const rowColor = route === 'direct' ? 'var(--color-success)' : route === 'proxy' ? 'var(--color-warning)' : 'var(--text-primary)';
      tr.style.color = rowColor;
      const routeBadge = route === 'direct'
        ? '<span style="background:var(--color-success-light);color:var(--color-success);padding:2px 6px;border-radius:4px;font-weight:600">DIRECT</span>'
        : route === 'proxy'
        ? '<span style="background:var(--color-warning-light);color:var(--color-warning);padding:2px 6px;border-radius:4px;font-weight:600">PROXY</span>'
        : '<span style="background:var(--bg-inset);color:var(--text-primary);padding:2px 6px;border-radius:4px">' + (e.route_type||'') + '</span>';
      tr.innerHTML = '<td class="lt-time">' + ts + '</td><td>' + port + '</td><td>' + (e.client_ip||'') + '</td><td>' + domain + '</td><td>' + (e.method||'') +
        '</td><td>' + (e.status_code||'') + '</td><td>' + routeBadge + '</td><td class="lt-hits">1</td><td class="lt-latency">' + (e.latency_ms||0) + 'ms</td><td class="lt-bytes">' +
        formatBytes(bytes) + '</td><td class="lt-error" style="color:var(--color-danger)">' + (e.error||'') + '</td>';
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
  if (!ranks.length) { c.innerHTML = '<p style="color:var(--text-muted);font-size:13px">No data</p>'; return; }
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
  if (!alerts.length) { c.innerHTML = '<p class="text-muted">No alerts</p>'; return; }
  let html = '';
  alerts.reverse().forEach(a => {
    const ts = new Date(a.timestamp).toLocaleString();
    const color = a.level === 'error' ? 'var(--color-danger)' : 'var(--color-warning)';
    html += '<div style="border-left:3px solid ' + color + ';padding:4px 8px;margin-bottom:4px">' +
      '<span style="color:' + color + '">[' + a.level + ']</span> ' + ts + ' — ' + a.message + '</div>';
  });
  c.innerHTML = html;
}

document.getElementById('clearAlertsBtn').addEventListener('click', async () => {
  await apiCall('POST', '/api/report/alerts/clear');
  loadAlerts();
});

// Tab-aware auto-refresh for report is handled in initSidebar().

// ── Phase 5 — Dashboard / Health ───────────────────────────
let dashInterval = null;

async function loadHealthStatus() {
  const r = await apiCall('GET', '/api/health/status');
  if (!r.ok) return;
  hideSkeleton('healthSkeleton', 'healthData');
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
  if (!groups.length) { container.innerHTML = '<p class="text-muted">No groups configured</p>'; return; }
  let html = '';
  groups.forEach(g => {
    html += '<div style="margin-bottom:16px">';
    html += '<h3 style="margin-bottom:6px">' + g.name + ' (' + g.alive + '/' + (g.proxies||[]).length + ' alive)</h3>';
    html += '<table class="mini-table"><tr><th>Host</th><th>Status</th><th>Latency</th><th>Avg</th><th>Success%</th><th>Weight</th><th>Conns</th><th>Ext IP</th></tr>';
    (g.proxies || []).forEach(p => {
      const dotClr = p.status === 'alive' ? 'var(--color-success)' : p.status === 'slow' ? 'var(--color-warning)' : p.status === 'dead' ? 'var(--color-danger)' : 'var(--text-muted)';
      html += '<tr><td>' + p.host + ':' + p.port + '</td>';
      html += '<td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotClr + ';margin-right:6px"></span>' + p.status + '</td>';
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

// ── Groups (one port range per group, e.g. per country) ─────
let editingGroup = null;

function escH(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function loadGroups() {
  const r = await apiCall('GET', '/api/groups');
  if (!r.ok) return;
  const groups = r.data.groups || [];
  const container = document.getElementById('groupsList');
  const summary = document.getElementById('groupsSummary');
  if (summary) {
    const total = groups.reduce((n, g) => n + (g.proxy_count || 0), 0);
    summary.textContent = groups.length ? '(' + groups.length + ' nhóm, ' + total + ' proxy)' : '';
  }
  // Populate port-mapping group select.
  const sel = document.getElementById('pmGroup');
  if (sel) sel.innerHTML = groups.map(g => '<option value="' + escH(g.name) + '">' + escH(g.name) + '</option>').join('');
  if (!container) return;
  if (!groups.length) { container.innerHTML = '<p class="text-muted">Chưa có nhóm nào. Tạo nhóm đầu tiên ở form bên dưới.</p>'; return; }

  let html = '<table class="mini-table"><tr><th>Nhóm</th><th>Dải port</th><th>Proxy / sức chứa</th><th>Còn trống</th><th>Sống</th><th>Chết</th><th></th></tr>';
  groups.forEach((g, idx) => {
    const ports = g.port_start ? g.port_start + ' – ' + g.port_end : '<span class="text-muted">chưa gán port</span>';
    const cap = g.port_start ? g.proxy_count + ' / ' + g.capacity : g.proxy_count;
    html += '<tr>';
    html += '<td style="font-weight:600;color:var(--color-accent)">' + escH(g.name) + '</td>';
    html += '<td>' + ports + '</td>';
    html += '<td>' + cap + '</td>';
    html += '<td>' + (g.port_start ? g.free : '—') + '</td>';
    html += '<td>' + (g.alive_count || 0) + '</td>';
    html += '<td>' + (g.dead_count || 0) + '</td>';
    html += '<td style="white-space:nowrap">';
    html += '<button class="btn btn-xs" data-gact="view" data-gidx="' + idx + '">Xem</button> ';
    html += '<button class="btn btn-xs" data-gact="copy" data-gidx="' + idx + '">Copy output</button> ';
    html += '<button class="btn btn-xs" data-gact="edit" data-gidx="' + idx + '">Sửa</button> ';
    html += '<button class="btn btn-xs btn-danger" style="padding:3px 8px;font-size:11px" data-gact="del" data-gidx="' + idx + '">Xoá</button>';
    html += '</td></tr>';
  });
  html += '</table>';
  container.innerHTML = html;
  container.querySelectorAll('button[data-gact]').forEach(btn => {
    btn.addEventListener('click', () => {
      const g = groups[parseInt(btn.dataset.gidx, 10)];
      if (!g) return;
      const act = btn.dataset.gact;
      if (act === 'view') viewGroup(g.name);
      else if (act === 'copy') copyGroupOutput(g.name);
      else if (act === 'edit') editGroup(g);
      else if (act === 'del') deleteGroup(g.name);
    });
  });
}

async function fetchGroupProxies(name) {
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/proxies');
  if (!r.ok) { setMsg('grpMsg', r.data.error || 'Không tải được nhóm', true); return null; }
  return r.data;
}

async function viewGroup(name) {
  const d = await fetchGroupProxies(name);
  const box = document.getElementById('groupDetail');
  if (!d || !box) return;
  const rows = d.proxies || [];
  let html = '<h3 style="margin-bottom:6px">' + escH(name) + ' — ' + rows.length + ' proxy ';
  html += '<button class="btn btn-xs" id="groupDetailClose">Đóng</button></h3>';
  if (!rows.length) { html += '<p class="text-muted">Nhóm chưa có proxy.</p>'; }
  else {
    html += '<div style="max-height:360px;overflow:auto"><table class="mini-table"><tr><th>#</th><th>Output (port trên VPS)</th><th>Proxy gốc</th><th>Loại</th><th>Trạng thái</th><th>Độ trễ</th></tr>';
    rows.forEach(p => {
      const dot = p.status === 'alive' ? 'var(--color-success)' : p.status === 'slow' ? 'var(--color-warning)' : p.status === 'dead' ? 'var(--color-danger)' : 'var(--text-muted)';
      html += '<tr><td>' + (p.index + 1) + '</td>';
      html += '<td>' + (p.output_addr ? escH(p.output_addr) : '<span class="text-muted">ngoài dải port</span>') + '</td>';
      html += '<td>' + escH(p.host) + ':' + p.port + (p.user ? ' <span class="text-muted">(' + escH(p.user) + ')</span>' : '') + '</td>';
      html += '<td>' + escH(p.type) + '</td>';
      html += '<td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dot + ';margin-right:6px"></span>' + escH(p.status || 'unknown') + '</td>';
      html += '<td>' + (p.latency_ms || 0) + 'ms</td></tr>';
    });
    html += '</table></div>';
  }
  box.innerHTML = html;
  document.getElementById('groupDetailClose').addEventListener('click', () => { box.innerHTML = ''; });
}

async function copyGroupOutput(name) {
  const d = await fetchGroupProxies(name);
  if (!d) return;
  const lines = (d.proxies || []).filter(p => p.output_addr).map(p => p.output_addr);
  if (!lines.length) { setMsg('grpMsg', 'Nhóm ' + name + ' chưa có port output (chưa gán dải port hoặc chưa có proxy)', true); return; }
  try {
    await copyToClipboard(lines.join('\n'));
    setMsg('grpMsg', 'Đã copy ' + lines.length + ' output của nhóm ' + name, false);
  } catch (e) {
    setMsg('grpMsg', 'Copy thất bại', true);
  }
}

function resetGroupForm() {
  editingGroup = null;
  document.getElementById('groupFormTitle').textContent = 'Tạo nhóm mới';
  const nameEl = document.getElementById('grpName');
  nameEl.value = ''; nameEl.readOnly = false;
  document.getElementById('grpPortStart').value = '';
  document.getElementById('grpPortEnd').value = '';
  document.getElementById('grpList').value = '';
  document.getElementById('grpListLabel').textContent = 'Danh sách proxy (mỗi dòng 1 proxy: host:port, host:port:user:pass hoặc user:pass@host:port)';
  document.getElementById('grpSaveBtn').textContent = 'Tạo nhóm';
  document.getElementById('grpAppendBtn').style.display = 'none';
  document.getElementById('grpCancelBtn').style.display = 'none';
}

function editGroup(g) {
  editingGroup = g.name;
  document.getElementById('groupFormTitle').textContent = 'Sửa nhóm ' + g.name;
  const nameEl = document.getElementById('grpName');
  nameEl.value = g.name; nameEl.readOnly = true;
  document.getElementById('grpPortStart').value = g.port_start || '';
  document.getElementById('grpPortEnd').value = g.port_end || '';
  document.getElementById('grpList').value = '';
  document.getElementById('grpListLabel').textContent = 'Danh sách proxy — để trống nếu chỉ đổi dải port. "Lưu" sẽ THAY toàn bộ danh sách, "Thêm vào cuối" giữ nguyên proxy cũ và port của chúng.';
  document.getElementById('grpSaveBtn').textContent = 'Lưu (thay danh sách)';
  document.getElementById('grpAppendBtn').style.display = '';
  document.getElementById('grpCancelBtn').style.display = '';
  document.getElementById('groupFormTitle').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function submitGroup(append) {
  const name = document.getElementById('grpName').value.trim();
  const ps = parseInt(document.getElementById('grpPortStart').value, 10) || 0;
  const pe = parseInt(document.getElementById('grpPortEnd').value, 10) || 0;
  const rawText = document.getElementById('grpList').value;
  const ptype = document.getElementById('grpType').value;
  if (!name) { setMsg('grpMsg', 'Chưa nhập tên nhóm', true); return; }
  if (pe && !ps) { setMsg('grpMsg', 'Có port kết thúc thì phải có port bắt đầu', true); return; }
  if (ps && pe && pe < ps) { setMsg('grpMsg', 'Port kết thúc nhỏ hơn port bắt đầu', true); return; }

  const body = { proxy_type: ptype };
  if (ps) { body.port_start = ps; if (pe) body.port_end = pe; }
  let r;
  if (editingGroup) {
    if (append && !rawText.trim()) { setMsg('grpMsg', 'Chưa có proxy nào để thêm', true); return; }
    if (rawText.trim()) { body.raw_text = rawText; body.append = !!append; }
    if (!append && rawText.trim() && !confirm('Thay toàn bộ danh sách proxy của nhóm ' + editingGroup + '?')) return;
    r = await apiCall('PUT', '/api/groups/' + encodeURIComponent(editingGroup), body);
  } else {
    body.name = name; body.raw_text = rawText; body.rotation_mode = 'roundrobin';
    r = await apiCall('POST', '/api/groups', body);
  }
  if (!r.ok) { setMsg('grpMsg', r.data.error || 'Thất bại', true); return; }
  let msg = 'Đã lưu nhóm ' + name + ': ' + (r.data.count || 0) + ' proxy';
  if (r.data.added !== undefined && append) msg = 'Đã thêm ' + r.data.added + ' proxy vào ' + name + ' (tổng ' + r.data.count + ')';
  if (r.data.skipped) msg += ', bỏ qua ' + r.data.skipped + ' dòng lỗi/trùng';
  setMsg('grpMsg', msg, false);
  resetGroupForm();
  loadGroups();
}

document.getElementById('grpSaveBtn').addEventListener('click', () => submitGroup(false));
document.getElementById('grpAppendBtn').addEventListener('click', () => submitGroup(true));
document.getElementById('grpCancelBtn').addEventListener('click', resetGroupForm);

async function deleteGroup(name) {
  if (!confirm('Xoá nhóm "' + name + '" cùng dải port của nó?')) return;
  const r = await apiCall('DELETE', '/api/groups/' + encodeURIComponent(name));
  if (!r.ok) { setMsg('grpMsg', r.data.error || 'Xoá thất bại', true); return; }
  if (editingGroup === name) resetGroupForm();
  const box = document.getElementById('groupDetail');
  if (box) box.innerHTML = '';
  setMsg('grpMsg', 'Đã xoá nhóm ' + name, false);
  loadGroups();
}

// ── Session proxies (groups with list history) ─────────────
let sessGroups = [];
let sessCur = null; // { name, port_start, port_end, proxies: [...] }

function sessName() { return document.getElementById('sessGroup').value; }

function fmtTime(unix) {
  if (!unix) return '';
  const d = new Date(unix * 1000);
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

// ── ShopSocks5 (lấy sock cho nhóm phiên) ───────────────────
async function ssLoadExclude() {
  const r = await apiCall('GET', '/api/config/shopsocks5/exclude');
  if (!r.ok) return;
  const info = document.getElementById('ssExclInfo');
  document.getElementById('ssExclUrl').value = r.data.url || '';
  if (!r.data.url) info.textContent = '— chưa dùng';
  else if (r.data.error) info.textContent = '— LỖI: ' + r.data.error;
  else info.textContent = '— đang loại trừ ' + r.data.count + ' IP';
}

document.getElementById('ssExclSave').addEventListener('click', async () => {
  const btn = document.getElementById('ssExclSave');
  btn.disabled = true;
  const r = await apiCall('POST', '/api/config/shopsocks5/exclude', { url: document.getElementById('ssExclUrl').value.trim() });
  btn.disabled = false;
  if (!r.ok) { setMsg('ssMsg', r.data.error || 'Thất bại', true); return; }
  setMsg('ssMsg', r.data.url ? 'Đã lưu: danh sách có ' + r.data.count + ' IP' : 'Đã tắt danh sách loại trừ', false);
  ssLoadExclude();
});

async function ssLoadAccount() {
  ssLoadExclude();
  const box = document.getElementById('ssAccount');
  const c = await apiCall('GET', '/api/config/shopsocks5');
  if (!c.ok) { box.textContent = ''; return; }
  document.getElementById('ssUser').value = c.data.user_name || '';
  if (!c.data.token_set) { box.textContent = 'Chưa nhập tài khoản ShopSocks5. Mở mục "Tài khoản ShopSocks5" bên dưới để nhập.'; return; }
  box.textContent = 'Đang đọc tài khoản…';
  const a = await apiCall('GET', '/api/config/shopsocks5/account');
  if (!a.ok) { box.textContent = 'Không đọc được tài khoản: ' + (a.data.error || 'lỗi'); return; }
  box.textContent = 'Tài khoản ' + a.data.user_name + ' · gói ' + a.data.plan_name + ' ' + a.data.plan_limit + '/ngày · còn ' +
    a.data.limit_today + ' lượt hôm nay · hết hạn ' + a.data.expired;
}

async function ssFetch(mode) {
  const name = sessName();
  if (!name) { setMsg('ssMsg', 'Chưa có nhóm phiên', true); return; }
  const body = {
    mode,
    qty: parseInt(document.getElementById('ssQty').value, 10) || 1,
    country: document.getElementById('ssCountry').value.trim(),
    state: document.getElementById('ssState').value.trim(),
    city: document.getElementById('ssCity').value.trim(),
    sock_type: document.getElementById('ssType').value,
    level: document.getElementById('ssLevel').value,
    unique: document.getElementById('ssUnique').checked,
  };
  if (mode === 'port') {
    body.ip_real = document.getElementById('ssIpReal').value.trim();
    body.output_port = parseInt(document.getElementById('ssPort').value, 10) || 0;
    if (!body.ip_real) { setMsg('ssMsg', 'Nhập IP thoát cần gọi lại', true); return; }
    if (!body.output_port) { setMsg('ssMsg', 'Nhập port muốn gắn', true); return; }
    // Only the IP matters when recalling: other filters could exclude it.
    body.country = body.state = body.city = body.sock_type = body.level = '';
    if (!confirm('Xin ShopSocks5 cấp lại IP ' + body.ip_real + ' và gắn vào port ' + body.output_port + '? Tốn 1 lượt nếu thành công.')) return;
  } else {
    const count = (sessCur && sessCur.proxies || []).length;
    let q = 'Lấy ' + body.qty + ' sock từ ShopSocks5 (trừ ' + body.qty + ' lượt)';
    q += mode === 'replace' ? ' và THAY ' + count + ' proxy hiện tại của nhóm ' + name + '? List cũ được lưu vào lịch sử.' : ' và thêm vào port trống của nhóm ' + name + '?';
    if (!confirm(q)) return;
  }
  const btns = ['ssAppendBtn', 'ssReplaceBtn', 'ssRecallBtn'].map(id => document.getElementById(id));
  btns.forEach(b => { b.disabled = true; });
  setMsg('ssMsg', 'Đang lấy sock…', false);
  const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(name) + '/shopsocks5', body);
  btns.forEach(b => { b.disabled = false; });
  if (!r.ok) { setMsg('ssMsg', r.data.error || 'Thất bại', true); await loadSessionGroup(); loadSessionHistory(); return; }
  let msg = 'Đã lấy ' + r.data.count + ' sock';
  if (r.data.duplicates) msg += ', bỏ ' + r.data.duplicates + ' sock trùng IP cũ / IP loại trừ (tổng trừ ' + r.data.spent + ' lượt)';
  if (r.data.count < r.data.requested) msg += r.data.duplicates ? ' — còn thiếu ' + (r.data.requested - r.data.count) + ' so với yêu cầu' : ' (yêu cầu ' + r.data.requested + ', kho chỉ còn chừng đó)';
  setMsg('ssMsg', msg, false);
  let html = '<table class="data-table"><thead><tr><th>Port</th><th>IP public</th><th>Vị trí</th><th>Nhà mạng</th><th>Loại</th><th>Rủi ro</th></tr></thead><tbody>';
  (r.data.socks || []).forEach(s => {
    html += '<tr><td>' + s.output_port + '</td><td>' + escH(s.external_ip || '') + '</td><td>' +
      escH([s.city, s.state, s.country].filter(Boolean).join(', ')) + '</td><td>' + escH(s.isp || '') + '</td><td>' +
      escH(s.sock_type || '') + '</td><td>' + escH(s.level || '') + '</td></tr>';
  });
  document.getElementById('ssResult').innerHTML = html + '</tbody></table>';
  await loadSessionTab();
  ssLoadAccount();
  // New socks are probed in the background; show the result when it lands.
  setTimeout(loadSessionGroup, 6000);
  setTimeout(loadSessionGroup, 15000);
}

document.getElementById('ssAppendBtn').addEventListener('click', () => ssFetch('append'));
document.getElementById('ssReplaceBtn').addEventListener('click', () => ssFetch('replace'));
document.getElementById('ssRecallBtn').addEventListener('click', () => ssFetch('port'));
document.getElementById('ssSaveBtn').addEventListener('click', async () => {
  const r = await apiCall('POST', '/api/config/shopsocks5', {
    user_name: document.getElementById('ssUser').value.trim(),
    api_token: document.getElementById('ssToken').value.trim(),
  });
  if (!r.ok) { setMsg('ssMsg', r.data.error || 'Thất bại', true); return; }
  document.getElementById('ssToken').value = '';
  setMsg('ssMsg', 'Đã lưu tài khoản ShopSocks5', false);
  ssLoadAccount();
});

// ── Tự giữ port luôn sống ──────────────────────────────────
async function akLoad() {
  const name = sessName();
  const stBox = document.getElementById('akStatus');
  const tag = document.getElementById('akState');
  if (!name) { stBox.textContent = ''; tag.textContent = ''; return; }
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/auto-keep');
  if (!r.ok) { stBox.textContent = ''; tag.textContent = ''; return; }
  const c = r.data.config || {}, st = r.data.status || {};
  document.getElementById('akEnabled').checked = !!c.enabled;
  document.getElementById('akUnique').checked = !!c.unique;
  document.getElementById('akTarget').value = c.target || 30;
  document.getElementById('akCheck').value = c.check_sec || 60;
  document.getElementById('akDead').value = c.dead_checks || 2;
  document.getElementById('akMax').value = c.max_per_day || 200;
  document.getElementById('akCountry').value = c.country || '';
  document.getElementById('akStateIn').value = c.state || '';
  document.getElementById('akCity').value = c.city || '';
  document.getElementById('akType').value = c.sock_type || '';
  document.getElementById('akLevel').value = c.level || '';
  tag.textContent = c.enabled ? '— ĐANG BẬT' : '— đang tắt';
  if (!c.enabled) { stBox.textContent = ''; return; }
  const first = r.data.port_start || 0;
  let t = 'Port ' + first + '–' + (first + c.target - 1) + ': ' + st.alive + ' sống, ' + st.dead + ' chết, ' + st.empty + ' trống' +
    (st.running ? ' (đang kiểm tra…)' : '') + '\n' +
    'Hôm nay: đã lấy ' + st.spent_today + '/' + c.max_per_day + ' sock, trong đó thay ' + st.replaced_today + ' sock chết' +
    (st.last_run ? ' · kiểm tra gần nhất ' + fmtTime(st.last_run) : ' · chưa kiểm tra lần nào');
  if (st.last_error) t += '\nLỗi gần nhất (' + fmtTime(st.last_error_at) + '): ' + st.last_error;
  stBox.textContent = t;
}

document.getElementById('akSaveBtn').addEventListener('click', async () => {
  const name = sessName();
  if (!name) { setMsg('akMsg', 'Chưa có nhóm phiên', true); return; }
  const body = {
    enabled: document.getElementById('akEnabled').checked,
    unique: document.getElementById('akUnique').checked,
    target: parseInt(document.getElementById('akTarget').value, 10) || 0,
    check_sec: parseInt(document.getElementById('akCheck').value, 10) || 0,
    dead_checks: parseInt(document.getElementById('akDead').value, 10) || 0,
    max_per_day: parseInt(document.getElementById('akMax').value, 10) || 0,
    country: document.getElementById('akCountry').value.trim(),
    state: document.getElementById('akStateIn').value.trim(),
    city: document.getElementById('akCity').value.trim(),
    sock_type: document.getElementById('akType').value,
    level: document.getElementById('akLevel').value,
  };
  if (body.enabled && !confirm('Bật tự giữ ' + body.target + ' port luôn sống cho nhóm ' + name + '?\n' +
    'Port trống và port chết sẽ tự lấy sock mới từ ShopSocks5, tối đa ' + body.max_per_day + ' lượt mỗi ngày.')) return;
  const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(name) + '/auto-keep', body);
  if (!r.ok) { setMsg('akMsg', r.data.error || 'Thất bại', true); return; }
  setMsg('akMsg', body.enabled ? 'Đã bật. Lần kiểm tra đầu chạy trong vài giây.' : 'Đã lưu (đang tắt)', false);
  akLoad();
  if (body.enabled) { setTimeout(() => { akLoad(); loadSessionGroup(); }, 20000); }
});
document.getElementById('akReloadBtn').addEventListener('click', () => { akLoad(); loadSessionGroup(); });

// ── API cho khách (đổi IP theo port) ───────────────────────
let saData = null;

function saLink(port, verb) {
  const key = saData && saData.port_keys && saData.port_keys[port];
  if (!key) return '';
  return window.location.origin + '/api/pub/port/' + port + (verb ? '/' + verb : '') + '?key=' + key + (verb === 'recall' ? '&ip=IP_CAN_GOI_LAI' : '');
}

function saRenderExample() {
  const port = parseInt(document.getElementById('saPort').value, 10);
  const ex = document.getElementById('saExample');
  if (!saLink(port, 'new')) { ex.textContent = 'Port không thuộc dải của nhóm.'; return; }
  ex.textContent = 'Đổi IP mới:   ' + saLink(port, 'new') + '\n' +
    '   (thêm &country=US&state=California&city=... nếu khách được chọn vị trí)\n' +
    'Gọi lại IP cũ: ' + saLink(port, 'recall') + '\n' +
    'Xem IP đang dùng: ' + saLink(port, '');
}

async function saLoad() {
  const name = sessName();
  saData = null;
  document.getElementById('saLinks').style.display = 'none';
  if (!name) return;
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/session-api');
  if (!r.ok) return;
  saData = r.data;
  document.getElementById('saEnabled').checked = !!saData.enabled;
  document.getElementById('saUnique').checked = !!saData.unique;
  document.getElementById('saCountry').value = saData.country || '';
  document.getElementById('saState').value = saData.state || '';
  document.getElementById('saCity').value = saData.city || '';
  if (saData.key) {
    document.getElementById('saType').value = saData.sock_type || '';
    document.getElementById('saLevel').value = saData.level || '';
    document.getElementById('saInterval').value = saData.min_interval_sec || 0;
  }
  if (saData.enabled && saData.port_keys) {
    document.getElementById('saLinks').style.display = '';
    const p = document.getElementById('saPort');
    if (!saData.port_keys[p.value]) p.value = saData.port_start;
    saRenderExample();
    saRenderKeys();
  }
}

function saRenderKeys() {
  const box = document.getElementById('saKeys');
  const keys = (saData && saData.keys) || [];
  if (!keys.length) { box.innerHTML = '<p class="text-muted text-sm">Chưa có key dùng chung.</p>'; return; }
  let html = '<table class="data-table"><thead><tr><th>Key</th><th>Port</th><th>Ghi chú</th><th></th></tr></thead><tbody>';
  keys.forEach((k, i) => {
    html += '<tr><td>' + escH(k.key) + '</td><td>' + escH(k.ports) + '</td><td>' + escH(k.note || '') + '</td>' +
      '<td><button class="btn btn-xs" data-sak-copy="' + i + '">Copy link mẫu</button> ' +
      '<button class="btn btn-xs btn-danger" data-sak-del="' + i + '">X</button></td></tr>';
  });
  box.innerHTML = html + '</tbody></table>';
  box.querySelectorAll('[data-sak-copy]').forEach(b => b.addEventListener('click', () => {
    const k = keys[+b.dataset.sakCopy];
    const base = window.location.origin + '/api/pub/port/PORT';
    copyToClipboard('Key: ' + k.key + ' | Port: ' + k.ports + '\n' +
      'Doi IP moi:    ' + base + '/new?key=' + k.key + '\n' +
      'Goi lai IP cu: ' + base + '/recall?key=' + k.key + '&ip=IP_CAN_GOI_LAI\n' +
      'Xem IP:        ' + base + '?key=' + k.key + '\n' +
      '(thay PORT bang so port can doi)');
    setMsg('saMsg', 'Đã copy link mẫu của key', false);
  }));
  box.querySelectorAll('[data-sak-del]').forEach(b => b.addEventListener('click', async () => {
    const k = keys[+b.dataset.sakDel];
    if (!confirm('Xóa key của "' + (k.note || k.ports) + '"? Khách dùng key này sẽ không đổi IP được nữa.')) return;
    const r = await apiCall('DELETE', '/api/groups/' + encodeURIComponent(sessName()) + '/session-api/keys', { key: k.key });
    if (!r.ok) { setMsg('saMsg', r.data.error || 'Thất bại', true); return; }
    saLoad();
  }));
}

document.getElementById('saKeyAdd').addEventListener('click', async () => {
  const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(sessName()) + '/session-api/keys', {
    ports: document.getElementById('saKeyPorts').value.trim(),
    note: document.getElementById('saKeyNote').value.trim(),
  });
  if (!r.ok) { setMsg('saMsg', r.data.error || 'Thất bại', true); return; }
  document.getElementById('saKeyPorts').value = '';
  document.getElementById('saKeyNote').value = '';
  setMsg('saMsg', 'Đã tạo key cho port ' + r.data.key.ports, false);
  saLoad();
});

async function saSave(regenerate) {
  const name = sessName();
  if (!name) { setMsg('saMsg', 'Chưa có nhóm phiên', true); return; }
  if (regenerate && !confirm('Đổi key của nhóm ' + name + '? Mọi link đã gửi cho khách sẽ hết hiệu lực.')) return;
  const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(name) + '/session-api', {
    enabled: document.getElementById('saEnabled').checked,
    unique: document.getElementById('saUnique').checked,
    country: document.getElementById('saCountry').value.trim(),
    state: document.getElementById('saState').value.trim(),
    city: document.getElementById('saCity').value.trim(),
    sock_type: document.getElementById('saType').value,
    level: document.getElementById('saLevel').value,
    min_interval_sec: parseInt(document.getElementById('saInterval').value, 10) || 0,
    regenerate: !!regenerate,
  });
  if (!r.ok) { setMsg('saMsg', r.data.error || 'Thất bại', true); return; }
  setMsg('saMsg', regenerate ? 'Đã đổi key' : 'Đã lưu', false);
  saLoad();
}

document.getElementById('saSaveBtn').addEventListener('click', () => saSave(false));
document.getElementById('saRegenBtn').addEventListener('click', () => saSave(true));
document.getElementById('saPort').addEventListener('input', saRenderExample);
document.getElementById('saCopyNew').addEventListener('click', () => {
  const l = saLink(parseInt(document.getElementById('saPort').value, 10), 'new');
  if (l) { copyToClipboard(l); setMsg('saMsg', 'Đã copy link đổi IP', false); }
});
document.getElementById('saCopyRecall').addEventListener('click', () => {
  const l = saLink(parseInt(document.getElementById('saPort').value, 10), 'recall');
  if (l) { copyToClipboard(l); setMsg('saMsg', 'Đã copy link gọi lại IP', false); }
});
document.getElementById('saCopyAll').addEventListener('click', () => {
  if (!saData || !saData.port_keys) return;
  const lines = Object.keys(saData.port_keys).map(Number).sort((a, b) => a - b).map(p => p + ' | ' + saLink(p, 'new'));
  copyToClipboard(lines.join('\n'));
  setMsg('saMsg', 'Đã copy ' + lines.length + ' link (port | link đổi IP)', false);
});

async function loadSessionTab() {
  ssLoadAccount();
  const r = await apiCall('GET', '/api/groups');
  if (!r.ok) return;
  const all = r.data.groups || [];
  sessGroups = all.filter(g => g.keep_history);
  const sel = document.getElementById('sessGroup');
  const prev = sel.value;
  sel.innerHTML = sessGroups.map(g => '<option value="' + escH(g.name) + '">' + escH(g.name) + '</option>').join('');
  if (prev && sessGroups.some(g => g.name === prev)) sel.value = prev;
  const others = all.filter(g => !g.keep_history);
  document.getElementById('sessEnableSel').innerHTML = others.map(g => '<option value="' + escH(g.name) + '">' + escH(g.name) + '</option>').join('');
  if (!sessGroups.length) {
    sessCur = null;
    document.getElementById('sessInfo').textContent = 'Chưa có nhóm phiên nào. Bấm "+ Nhóm phiên mới" để tạo, hoặc bật lịch sử cho một nhóm có sẵn.';
    document.getElementById('sessNewBox').style.display = '';
    ['sessCurrent', 'sessHistory', 'sessSnapshot', 'sessSearchResult'].forEach(id => { document.getElementById(id).innerHTML = ''; });
    document.getElementById('sessCurCount').textContent = '';
    return;
  }
  await loadSessionGroup();
}

async function loadSessionGroup() {
  const name = sessName();
  if (!name) return;
  saLoad();
  akLoad();
  document.getElementById('sessSnapshot').innerHTML = '';
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/proxies');
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Không tải được nhóm', true); return; }
  sessCur = r.data;
  const rows = sessCur.proxies || [];
  const g = sessGroups.find(x => x.name === name) || {};
  const withIP = rows.filter(p => p.external_ip).length;
  let info = 'Dải port: ' + (sessCur.port_start ? sessCur.port_start + ' – ' + sessCur.port_end + ' (' + (g.capacity || 0) + ' port)' : 'chưa gán');
  info += ' · ' + rows.length + ' proxy · ' + withIP + ' đã có IP public';
  document.getElementById('sessInfo').textContent = info;
  document.getElementById('sessCurCount').textContent = '(' + rows.length + ')';

  const box = document.getElementById('sessCurrent');
  if (!rows.length) { box.innerHTML = '<p class="text-muted">Nhóm chưa có proxy. Dán list ở ô "Thay list".</p>'; }
  else {
    let html = '<div style="max-height:380px;overflow:auto"><table class="mini-table"><tr><th>Port output</th><th>Proxy gốc</th><th>User</th><th>IP public</th><th>Trạng thái</th></tr>';
    rows.forEach(p => {
      const dot = p.status === 'alive' ? 'var(--color-success)' : p.status === 'slow' ? 'var(--color-warning)' : p.status === 'dead' ? 'var(--color-danger)' : 'var(--text-muted)';
      html += '<tr><td>' + (p.output_port || '<span class="text-muted">ngoài dải</span>') + '</td>';
      html += '<td>' + escH(p.host) + ':' + p.port + '</td>';
      html += '<td>' + escH(p.user || '') + '</td>';
      html += '<td>' + (p.external_ip ? escH(p.external_ip) : '<span class="text-muted">chưa kiểm tra</span>') + '</td>';
      html += '<td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dot + ';margin-right:6px"></span>' + escH(p.status || 'unknown') + '</td></tr>';
    });
    html += '</table></div>';
    box.innerHTML = html;
  }
  await loadSessionHistory();
  await loadSessionIps();
}

async function loadSessionHistory() {
  const name = sessName();
  const box = document.getElementById('sessHistory');
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/history');
  if (!r.ok) { box.innerHTML = '<p class="text-muted">' + escH(r.data.error || 'Không tải được lịch sử') + '</p>'; return; }
  const snaps = r.data.snapshots || [];
  if (!snaps.length) { box.innerHTML = '<p class="text-muted">Chưa có list nào trong lịch sử. List cũ sẽ xuất hiện ở đây sau lần thay list đầu tiên.</p>'; return; }
  const reasons = { replace: 'Thay list', restore: 'Trước khi khôi phục', swap: 'Bị thay ở 1 port', auto: 'Tự thay vì chết', fetched: 'Sock đã lấy nhưng chưa gắn' };
  let html = '<div style="max-height:300px;overflow:auto"><table class="mini-table"><tr><th>Thời gian</th><th>Lý do</th><th>Số proxy</th><th>Có IP public</th><th></th></tr>';
  snaps.forEach((sn, i) => {
    html += '<tr><td>' + fmtTime(sn.at) + '</td><td>' + (reasons[sn.reason] || escH(sn.reason)) + '</td><td>' + sn.count + '</td><td>' + sn.with_ip + '</td>';
    html += '<td style="white-space:nowrap"><button class="btn btn-xs" data-sact="view" data-sidx="' + i + '">Xem</button> ';
    html += '<button class="btn btn-xs" data-sact="restore" data-sidx="' + i + '">Khôi phục list này</button></td></tr>';
  });
  html += '</table></div>';
  box.innerHTML = html;
  box.querySelectorAll('button[data-sact]').forEach(btn => {
    btn.addEventListener('click', () => {
      const sn = snaps[parseInt(btn.dataset.sidx, 10)];
      if (!sn) return;
      if (btn.dataset.sact === 'view') viewSnapshot(sn);
      else restoreSnapshot(sn);
    });
  });
}

// ── Thống kê IP public đã lấy ──────────────────────────────
let sessIps = [];

function sessIpsShown() {
  const q = document.getElementById('sessIpsFilter').value.trim().toLowerCase();
  if (!q) return sessIps;
  return sessIps.filter(p => (p.external_ip + ' ' + (p.country || '') + ' ' + (p.output_port || '') + ' ' + p.host).toLowerCase().includes(q));
}

function renderSessionIps() {
  const box = document.getElementById('sessIps');
  if (!sessIps.length) { box.innerHTML = '<p class="text-muted">Chưa ghi nhận IP public nào.</p>'; return; }
  const rows = sessIpsShown();
  const max = 500;
  let html = '<div style="max-height:380px;overflow:auto"><table class="mini-table"><tr><th>#</th><th>IP public</th><th>Nước</th><th>Trạng thái</th><th>Port</th><th>Proxy gốc</th><th>Lần đầu lưu</th><th>Gắn lại vào port</th></tr>';
  rows.slice(0, max).forEach((p, i) => {
    html += '<tr><td>' + (i + 1) + '</td><td>' + escH(p.external_ip) + '</td><td>' + escH(p.country || '—') + '</td>';
    html += '<td>' + (p.in_use ? '<b>Đang dùng</b>' : 'Đã thay lúc ' + fmtTime(p.last_at)) + '</td>';
    html += '<td>' + (p.output_port || '—') + '</td><td>' + escH(p.host) + ':' + p.port + '</td>';
    html += '<td>' + (p.first_at ? fmtTime(p.first_at) : '—') + '</td>';
    html += '<td style="white-space:nowrap">' + (p.in_use ? '<span class="text-muted">—</span>' : attachCell(p.snapshot_id, p.index, p.output_port)) + '</td></tr>';
  });
  html += '</table></div>';
  if (rows.length > max) html += '<p class="text-muted text-sm">Hiện ' + max + '/' + rows.length + ' dòng. Dùng ô lọc, hoặc Copy / Tải CSV để lấy đủ.</p>';
  box.innerHTML = html;
  wireAttach(box);
}

async function loadSessionIps() {
  const name = sessName();
  const box = document.getElementById('sessIps');
  sessIps = [];
  document.getElementById('sessIpsCount').textContent = '';
  if (!name) { box.innerHTML = ''; return; }
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(name) + '/ips');
  if (!r.ok) { box.innerHTML = '<p class="text-muted">' + escH(r.data.error || 'Không tải được thống kê') + '</p>'; return; }
  sessIps = r.data.ips || [];
  let txt = '— ' + r.data.total + ' IP khác nhau: ' + r.data.in_use + ' đang dùng, ' + r.data.history + ' trong lịch sử';
  if (r.data.current_without_ip) txt += ' (' + r.data.current_without_ip + ' proxy đang dùng chưa có IP public)';
  document.getElementById('sessIpsCount').textContent = txt;
  renderSessionIps();
}

document.getElementById('sessIpsFilter').addEventListener('input', renderSessionIps);
document.getElementById('sessIpsReload').addEventListener('click', loadSessionIps);
document.getElementById('sessIpsCopy').addEventListener('click', () => {
  const rows = sessIpsShown();
  if (!rows.length) return;
  copyToClipboard(rows.map(p => p.external_ip).join('\n'));
  setMsg('sessMsg', 'Đã copy ' + rows.length + ' IP', false);
});
document.getElementById('sessIpsCsv').addEventListener('click', () => {
  const rows = sessIpsShown();
  if (!rows.length) return;
  const iso = t => t ? new Date(t * 1000).toISOString() : '';
  const lines = ['ip_public,nuoc,trang_thai,port,proxy_goc,lan_dau_luu,lan_cuoi_luu'].concat(rows.map(p =>
    [p.external_ip, p.country || '', p.in_use ? 'dang_dung' : 'lich_su', p.output_port || '', p.host + ':' + p.port, iso(p.first_at), iso(p.last_at)].join(',')));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
  a.download = 'ip-public-' + sessName() + '.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// defaultAttachPort: the port the proxy used to hold if it is still inside
// the range and not past the end of the current list, else the next free one.
function defaultAttachPort(oldPort) {
  if (!sessCur || !sessCur.port_start) return '';
  const count = (sessCur.proxies || []).length;
  const nextFree = sessCur.port_start + count;
  if (oldPort && oldPort >= sessCur.port_start && oldPort <= sessCur.port_end && oldPort <= nextFree) return oldPort;
  return nextFree <= sessCur.port_end ? nextFree : sessCur.port_start;
}

// attachCell renders the "port + Gắn" control for one history row.
function attachCell(snapshotId, index, oldPort) {
  return '<input type="number" style="width:90px;display:inline-block" value="' + defaultAttachPort(oldPort) + '" data-aport> ' +
    '<button class="btn btn-xs btn-primary" data-attach data-snap="' + escH(snapshotId) + '" data-row="' + index + '">Gắn</button>';
}

function wireAttach(container) {
  container.querySelectorAll('button[data-attach]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const input = btn.parentElement.querySelector('input[data-aport]');
      const port = parseInt(input.value, 10);
      if (!port) { setMsg('sessMsg', 'Chưa nhập port', true); return; }
      const cur = (sessCur && sessCur.proxies || []).find(p => p.output_port === port);
      const q = cur ? 'Port ' + port + ' đang gắn ' + cur.host + ':' + cur.port + '. Thay bằng proxy này? (proxy đang gắn sẽ được lưu vào lịch sử)' : 'Gắn proxy này vào port ' + port + '?';
      if (!confirm(q)) return;
      const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(sessName()) + '/attach',
        { id: btn.dataset.snap, index: parseInt(btn.dataset.row, 10), output_port: port });
      if (!r.ok) { setMsg('sessMsg', r.data.error || 'Gắn thất bại', true); return; }
      setMsg('sessMsg', 'Đã gắn vào port ' + port + (r.data.replaced ? ' (thay cho ' + r.data.replaced + ')' : ''), false);
      await loadSessionGroup();
    });
  });
}

async function viewSnapshot(sn) {
  const box = document.getElementById('sessSnapshot');
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(sessName()) + '/history?id=' + encodeURIComponent(sn.id));
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Không tải được list', true); return; }
  const rows = r.data.proxies || [];
  let html = '<h3 style="margin-bottom:6px">List lúc ' + fmtTime(sn.at) + ' — ' + rows.length + ' proxy <button class="btn btn-xs" id="sessSnapClose">Đóng</button></h3>';
  html += '<div style="max-height:380px;overflow:auto"><table class="mini-table"><tr><th>Port cũ</th><th>Proxy gốc</th><th>User</th><th>IP public</th><th>Gắn lại vào port</th></tr>';
  rows.forEach(p => {
    html += '<tr><td>' + (p.output_port || '—') + '</td><td>' + escH(p.host) + ':' + p.port + '</td><td>' + escH(p.user || '') + '</td>';
    html += '<td>' + (p.external_ip ? escH(p.external_ip) : '<span class="text-muted">không ghi nhận</span>') + '</td>';
    html += '<td style="white-space:nowrap">' + attachCell(sn.id, p.index, p.output_port) + '</td></tr>';
  });
  html += '</table></div>';
  box.innerHTML = html;
  document.getElementById('sessSnapClose').addEventListener('click', () => { box.innerHTML = ''; });
  wireAttach(box);
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function restoreSnapshot(sn) {
  if (!confirm('Khôi phục list lúc ' + fmtTime(sn.at) + ' (' + sn.count + ' proxy)? List hiện tại sẽ được lưu vào lịch sử.')) return;
  const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(sessName()) + '/history/restore', { id: sn.id });
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Khôi phục thất bại', true); return; }
  setMsg('sessMsg', 'Đã khôi phục ' + r.data.count + ' proxy', false);
  await loadSessionGroup();
}

async function sessSubmitList(append) {
  const name = sessName();
  if (!name) { setMsg('sessMsg', 'Chưa có nhóm phiên', true); return; }
  const rawText = document.getElementById('sessList').value;
  if (!rawText.trim()) { setMsg('sessMsg', 'Chưa dán list', true); return; }
  const count = (sessCur && sessCur.proxies || []).length;
  if (!append && count && !confirm('Thay ' + count + ' proxy hiện tại của nhóm ' + name + ' bằng list mới? List cũ được lưu vào lịch sử.')) return;
  const r = await apiCall('PUT', '/api/groups/' + encodeURIComponent(name),
    { raw_text: rawText, proxy_type: document.getElementById('sessType').value, append: !!append });
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Thất bại', true); return; }
  let msg = append ? 'Đã thêm ' + r.data.added + ' proxy (tổng ' + r.data.count + ')' : 'Đã thay list: ' + r.data.count + ' proxy';
  if (r.data.skipped) msg += ', bỏ qua ' + r.data.skipped + ' dòng lỗi/trùng';
  setMsg('sessMsg', msg, false);
  document.getElementById('sessList').value = '';
  await loadSessionGroup();
}

async function sessSearch() {
  const q = document.getElementById('sessSearch').value.trim();
  const box = document.getElementById('sessSearchResult');
  if (!sessName()) return;
  if (q.length < 3) { box.innerHTML = '<p class="text-muted">Nhập ít nhất 3 ký tự.</p>'; return; }
  const r = await apiCall('GET', '/api/groups/' + encodeURIComponent(sessName()) + '/search?ip=' + encodeURIComponent(q));
  if (!r.ok) { box.innerHTML = '<p class="text-muted">' + escH(r.data.error || 'Tìm thất bại') + '</p>'; return; }
  const hits = r.data.hits || [];
  if (!hits.length) { box.innerHTML = '<p class="text-muted">Không tìm thấy. IP public chỉ có khi proxy đã được kiểm tra (nút "Kiểm tra IP public") trước lúc thay list.</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Ở đâu</th><th>Port</th><th>Proxy gốc</th><th>User</th><th>IP public</th><th>Gắn lại vào port</th></tr>';
  hits.forEach(h => {
    const where = h.where === 'current' ? '<b>Đang dùng</b>' : 'Lịch sử ' + fmtTime(h.at);
    html += '<tr><td>' + where + '</td><td>' + (h.output_port || '—') + '</td><td>' + escH(h.host) + ':' + h.port + '</td><td>' + escH(h.user || '') + '</td>';
    html += '<td>' + escH(h.external_ip || '') + '</td>';
    html += '<td style="white-space:nowrap">' + (h.where === 'history' ? attachCell(h.snapshot_id, h.index, h.output_port) : '<span class="text-muted">đang ở port ' + (h.output_port || '?') + '</span>') + '</td></tr>';
  });
  html += '</table>';
  if (r.data.truncated) html += '<p class="text-muted text-sm">Quá nhiều kết quả, chỉ hiện 200 dòng đầu. Nhập IP đầy đủ hơn.</p>';
  box.innerHTML = html;
  wireAttach(box);
}

document.getElementById('sessGroup').addEventListener('change', () => { document.getElementById('sessSearchResult').innerHTML = ''; loadSessionGroup(); });
document.getElementById('sessReplaceBtn').addEventListener('click', () => sessSubmitList(false));
document.getElementById('sessAppendBtn').addEventListener('click', () => sessSubmitList(true));
document.getElementById('sessSearchBtn').addEventListener('click', sessSearch);
document.getElementById('sessSearch').addEventListener('keydown', e => { if (e.key === 'Enter') sessSearch(); });
document.getElementById('sessNewToggle').addEventListener('click', () => {
  const b = document.getElementById('sessNewBox');
  b.style.display = b.style.display === 'none' ? '' : 'none';
});

document.getElementById('sessCopyBtn').addEventListener('click', async () => {
  const lines = (sessCur && sessCur.proxies || []).filter(p => p.output_addr).map(p => p.output_addr);
  if (!lines.length) { setMsg('sessMsg', 'Nhóm chưa có port output', true); return; }
  try { await copyToClipboard(lines.join('\n')); setMsg('sessMsg', 'Đã copy ' + lines.length + ' output', false); }
  catch (e) { setMsg('sessMsg', 'Copy thất bại', true); }
});

document.getElementById('sessCheckBtn').addEventListener('click', async () => {
  const name = sessName();
  if (!name) return;
  const btn = document.getElementById('sessCheckBtn');
  btn.disabled = true; btn.textContent = 'Đang kiểm tra…';
  try {
    const r = await apiCall('POST', '/api/groups/' + encodeURIComponent(name) + '/check-ip');
    if (!r.ok) { setMsg('sessMsg', r.data.error || 'Kiểm tra thất bại', true); return; }
    setMsg('sessMsg', 'Đã kiểm tra ' + r.data.checked + ' proxy: ' + r.data.alive + ' sống, ' + r.data.with_ip + ' có IP public', false);
    await loadSessionGroup();
  } finally {
    btn.disabled = false; btn.textContent = 'Kiểm tra IP public';
  }
});

document.getElementById('sessNewBtn').addEventListener('click', async () => {
  const name = document.getElementById('sessNewName').value.trim();
  const ps = parseInt(document.getElementById('sessNewStart').value, 10) || 0;
  const pe = parseInt(document.getElementById('sessNewEnd').value, 10) || 0;
  if (!name || !ps || !pe) { setMsg('sessMsg', 'Cần tên nhóm, port bắt đầu và port kết thúc', true); return; }
  const r = await apiCall('POST', '/api/groups', { name, port_start: ps, port_end: pe, raw_text: '', keep_history: true });
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Tạo thất bại', true); return; }
  setMsg('sessMsg', 'Đã tạo nhóm phiên ' + name, false);
  document.getElementById('sessNewBox').style.display = 'none';
  await loadSessionTab();
  document.getElementById('sessGroup').value = name;
  await loadSessionGroup();
});

document.getElementById('sessEnableBtn').addEventListener('click', async () => {
  const name = document.getElementById('sessEnableSel').value;
  if (!name) { setMsg('sessMsg', 'Không còn nhóm nào để bật', true); return; }
  const r = await apiCall('PUT', '/api/groups/' + encodeURIComponent(name), { keep_history: true });
  if (!r.ok) { setMsg('sessMsg', r.data.error || 'Thất bại', true); return; }
  setMsg('sessMsg', 'Đã bật lịch sử cho nhóm ' + name, false);
  document.getElementById('sessNewBox').style.display = 'none';
  await loadSessionTab();
  document.getElementById('sessGroup').value = name;
  await loadSessionGroup();
});

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
  if (!portMappings.length) { c.innerHTML = '<p class="text-muted">No mappings</p>'; return; }
  let html = '<table class="mini-table"><tr><th>Start</th><th>End</th><th>Group</th><th></th></tr>';
  portMappings.forEach((m, i) => {
    html += '<tr><td>' + m.port_start + '</td><td>' + m.port_end + '</td><td>' + m.group_name + '</td>';
    html += '<td><button class="btn btn-xs" class="btn-danger" onclick="removePM(' + i + ')">X</button></td></tr>';
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
  setMsg('pmMsg', 'Saved & applied', false);
  loadGroups();
});

// ── Import Sources ─────────────────────────────────────────
async function loadImportSources() {
  const r = await apiCall('GET', '/api/import/sources');
  if (!r.ok) return;
  const sources = r.data.sources || [];
  const c = document.getElementById('importSourcesList');
  if (!sources.length) { c.innerHTML = '<p class="text-muted">No sources</p>'; return; }
  let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">';
  sources.forEach(s => {
    html += '<div style="background:var(--bg-inset);border:1px solid var(--border-color);border-radius:8px;padding:12px">';
    html += '<div style="font-weight:600;color:var(--color-accent)">' + s.name + '</div>';
    html += '<div style="font-size:11px;color:var(--text-muted);word-break:break-all">' + s.url + '</div>';
    html += '<div style="font-size:12px;color:var(--text-muted);margin-top:4px">Group: ' + s.group_name + ' · ' + s.proxy_type + '</div>';
    html += '<div style="font-size:12px;color:var(--text-muted)">Interval: ' + s.interval_sec + 's · Last: ' + (s.last_count||0) + ' proxies</div>';
    html += '<div style="margin-top:8px">';
    html += '<button class="btn btn-xs" onclick="fetchImportNow(\'' + s.name + '\')">Fetch Now</button>';
    html += ' <button class="btn btn-xs" class="btn-danger" onclick="deleteImport(\'' + s.name + '\')">Delete</button>';
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

// Tab-aware refresh is handled in initSidebar().

// ── Init ───────────────────────────────────────────────────
async function loadAppVersion() {
  const r = await apiCall('GET', '/api/system/info');
  if (r.ok && r.data.version) {
    document.getElementById('appVersion').textContent = r.data.version;
  }
}

async function initAll() {
  loadAppVersion();
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
  copyToClipboard(s).then(() => alert('Copied'), () => alert('Copy failed'));
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
// Phase 6 tab loading is handled in initSidebar().
// Auto-refresh system info on settings tab every 10s.
setInterval(()=>{
  if(document.getElementById('tab-settings')?.style.display !== 'none') loadSystemInfo();
}, 10000);

document.addEventListener('DOMContentLoaded', ()=>{ applyRolePermissions(); });
document.addEventListener('DOMContentLoaded', initAll);
