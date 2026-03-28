// Firewall4AI Admin UI
const API = '';
let pollInterval = null;
let lastLogID = 0;

// Edit state trackers
let editingRule = null;       // null = adding, { host, pathPrefix, skillID, sourceIP } = editing
let editingImageRule = null;  // null = adding, { host, skillID, sourceIP } = editing
let editingPackageRule = null; // null = adding, { host, skillID, sourceIP } = editing
let editingLibraryRule = null; // null = adding, { host, skillID, sourceIP } = editing
let editingSkillID = null;    // null = creating, string = editing
let editingCredID = null;     // null = creating, string = editing
let editingAgentID = null;    // null = creating, string = editing
let editingDBID = null;       // null = creating, string = editing

// Cached data for edit lookups
let currentApprovals = [];
let currentImages = [];
let currentPackages = [];
let currentLibraries = [];
let currentSkills = [];
let currentCredentials = [];
let currentCategories = [];
let currentLogs = [];
let currentAgents = [];
let currentDatabases = [];

// Pagination state per page type
const PAGE_SIZE = 50;
let pageState = {
  url: { offset: 0, total: 0 },
  image: { offset: 0, total: 0 },
  package: { offset: 0, total: 0 },
  library: { offset: 0, total: 0 },
};

// Selection state for bulk actions
let selectedApprovals = new Set();
let selectedImages = new Set();
let selectedPackages = new Set();
let selectedLibraries = new Set();

// Currently filtered items (for select-all and bulk operations)
let currentFilteredApprovals = [];
let currentFilteredImages = [];
let currentFilteredPackages = [];
let currentFilteredLibraries = [];

// --- Navigation ---
function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  location.hash = page;
  if (page === 'dashboard') loadDashboard();
  if (page === 'agents') loadAgents();
  if (page === 'approvals') loadApprovals();
  if (page === 'images') loadImages();
  if (page === 'packages') loadPackages();
  if (page === 'libraries') loadLibraries();
  if (page === 'skills') loadSkills();
  if (page === 'credentials') loadCredentials();
  if (page === 'logs') loadLogs();
  if (page === 'system') loadSystem();
}

// --- API helpers ---
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API + path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text);
  }
  return res.json();
}

// --- Skill display helper ---
function formatSkillID(skillID) {
  if (!skillID) return '<span class="badge-status approved">global</span>';
  const skill = currentSkills.find(s => s.id === skillID);
  return skill ? esc(skill.name) : esc(skillID);
}

function skillNameByID(id) {
  const s = currentSkills.find(s => s.id === id);
  return s ? s.name : id;
}

// --- Source IP display helper ---
function formatSourceIP(sourceIP) {
  if (!sourceIP) return '<span class="badge-status approved">all VMs</span>';
  return esc(sourceIP);
}

// --- Path prefix display helper ---
function formatPathPrefix(pathPrefix) {
  if (!pathPrefix) return '<span class="badge-status approved">all paths</span>';
  return '<code>' + esc(pathPrefix) + '</code>';
}

// --- Dashboard ---
async function loadDashboard() {
  try {
    const [stats, pending, pendingImages, pendingPkgs, pendingLibs] = await Promise.all([
      api('GET', '/api/logs/stats'),
      api('GET', '/api/approvals/pending'),
      api('GET', '/api/images/pending'),
      api('GET', '/api/packages/pending'),
      api('GET', '/api/libraries/pending'),
      refreshSkills(),
    ]);
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-allowed').textContent = stats.allowed || 0;
    document.getElementById('stat-denied').textContent = stats.denied || 0;
    document.getElementById('stat-pending').textContent = stats.pending || 0;
    document.getElementById('pending-count').textContent = (pending.length || 0) + (pendingImages.length || 0) + (pendingPkgs.length || 0) + (pendingLibs.length || 0);
    // Update sidebar badges
    updateBadge('approval-badge', pending);
    updateBadge('image-badge', pendingImages);
    updateBadge('package-badge', pendingPkgs);
    updateBadge('library-badge', pendingLibs);
    // Recent pending (all types combined)
    const tbody = document.getElementById('dash-pending-tbody');
    tbody.innerHTML = '';
    const allPending = [
      ...(pending || []).map(a => ({ ...a, _type: 'host' })),
      ...(pendingImages || []).map(a => ({ ...a, _type: 'image' })),
      ...(pendingPkgs || []).map(a => ({ ...a, _type: 'package' })),
      ...(pendingLibs || []).map(a => ({ ...a, _type: 'library' })),
    ];
    if (allPending.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No pending approvals</td></tr>';
    } else {
      allPending.slice(0, 10).forEach(a => {
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const pathDisplay = a._type === 'host' ? formatPathPrefix(a.path_prefix) : '';
        const apiPathMap = { host: '/api/approvals/decide', image: '/api/images/decide', package: '/api/packages/decide', library: '/api/libraries/decide' };
        const apiPath = apiPathMap[a._type] || '/api/approvals/decide';
        const typeLabelMap = { image: 'image', package: 'package', library: 'library' };
        const typeLabel = typeLabelMap[a._type] ? '<span class="badge-status pending">' + typeLabelMap[a._type] + '</span> ' : '';
        const pp = a.path_prefix || '';
        const approveBtn = `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','approved')">Approve</button>`;
        const vmBtn = a.source_ip ? `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','','${esc(a.source_ip)}','${esc(pp)}','approved')" title="Approve for this VM">Approve VM</button>` : '';
        const globalBtn = (a.skill_id || a.source_ip) ? `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','','','${esc(pp)}','approved')" title="Approve for all agents">Approve Global</button>` : '';
        const denyBtn = `<button class="btn btn-danger btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','denied')">Deny</button>`;
        const hostDisplay = (a._type === 'package' || a._type === 'library')
          ? formatLibraryType(a.host) + ' <strong>' + formatLibraryName(a.host) + '</strong>'
          : '<strong>' + esc(a.host) + '</strong>';
        tbody.innerHTML += `<tr>
          <td>${typeLabel}${hostDisplay}</td>
          <td>${pathDisplay}</td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td>${timeAgo(a.created_at)}</td>
          <td>${approveBtn} ${vmBtn} ${globalBtn} ${denyBtn}</td>
        </tr>`;
      });
    }
  } catch (e) {
    console.error('Dashboard load error:', e);
  }
}

async function decideDash(apiPath, host, skillID, sourceIP, pathPrefix, status) {
  try {
    await api('POST', apiPath, { host, skill_id: skillID, source_ip: sourceIP, path_prefix: pathPrefix, status });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function updateBadge(id, items) {
  const badge = document.getElementById(id);
  if (!badge) return;
  if (items && items.length > 0) {
    badge.textContent = items.length;
    badge.style.display = 'inline';
  } else {
    badge.style.display = 'none';
  }
}

// --- Filtering ---
function getFilter(prefix) {
  return {
    category: document.getElementById('filter-' + prefix + '-category')?.value || '',
    skillID: document.getElementById('filter-' + prefix + '-skill')?.value || '',
    ip: document.getElementById('filter-' + prefix + '-ip')?.value || '',
    status: document.getElementById('filter-' + prefix + '-status')?.value || '',
  };
}

function matchesFilter(item, filter) {
  if (filter.category && (item.category || '') !== filter.category) return false;
  if (filter.skillID && (item.skill_id || '') !== filter.skillID) return false;
  if (filter.ip && (item.source_ip || '') !== filter.ip) return false;
  if (filter.status && item.status !== filter.status) return false;
  if (filter.type && getLibraryType(item.host) !== filter.type) return false;
  return true;
}

// Extract library type from the host field (format: "type:name").
function getLibraryType(host) {
  if (!host) return '';
  const idx = host.indexOf(':');
  if (idx < 0) return '';
  return host.substring(0, idx);
}

// Extract library name from the host field (format: "type:name").
function getLibraryName(host) {
  if (!host) return host;
  const idx = host.indexOf(':');
  if (idx < 0) return host;
  return host.substring(idx + 1);
}

// Type label mapping — built dynamically from data, with known defaults.
const typeLabels = {
  golang: 'Go', npm: 'npm', pypi: 'PyPI', nuget: 'NuGet',
  debian: 'Debian', alpine: 'Alpine', ubuntu: 'Ubuntu',
  rust: 'Rust', powershell: 'PowerShell',
};

// Get the official web page URL for a library/package by type and name.
function getLibraryUrl(host) {
  const t = getLibraryType(host);
  const name = getLibraryName(host);
  if (!t || !name) return '';
  const urls = {
    debian: 'https://packages.debian.org/' + encodeURIComponent(name),
    ubuntu: 'https://packages.ubuntu.com/' + encodeURIComponent(name),
    alpine: 'https://pkgs.alpinelinux.org/packages?name=' + encodeURIComponent(name),
    golang: 'https://pkg.go.dev/' + name,
    npm: 'https://www.npmjs.com/package/' + name,
    pypi: 'https://pypi.org/project/' + encodeURIComponent(name),
    nuget: 'https://www.nuget.org/packages/' + encodeURIComponent(name),
    rust: 'https://crates.io/crates/' + encodeURIComponent(name),
    powershell: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(name),
  };
  return urls[t] || '';
}

// Format library name as a link to its official page, or plain text if no URL.
function formatLibraryName(host) {
  const name = esc(getLibraryName(host));
  const url = getLibraryUrl(host);
  if (url) {
    return '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + name + '</a>';
  }
  return name;
}

// Format library type as a badge.
function formatLibraryType(host) {
  const t = getLibraryType(host);
  return '<span class="badge-status approved">' + esc(typeLabels[t] || t) + '</span>';
}

// Get type-aware filter (used by packages and libraries pages).
function getTypedFilter(prefix) {
  return {
    type: document.getElementById('filter-' + prefix + '-type')?.value || '',
    category: document.getElementById('filter-' + prefix + '-category')?.value || '',
    skillID: document.getElementById('filter-' + prefix + '-skill')?.value || '',
    ip: document.getElementById('filter-' + prefix + '-ip')?.value || '',
    status: document.getElementById('filter-' + prefix + '-status')?.value || '',
  };
}

// Populate the type filter dropdown from the data.
function populateTypeFilter(prefix, items) {
  const types = [...new Set(items.map(a => getLibraryType(a.host)).filter(Boolean))].sort();
  const opts = types.map(t => ({ value: t, label: typeLabels[t] || t }));
  populateSelect('filter-' + prefix + '-type', opts, 'All types');
}

// Populate a type selector in a modal from an item list or all known types of a kind.
function populateTypeSelect(selectId, typeKeys) {
  const el = document.getElementById(selectId);
  if (!el) return;
  const current = el.value;
  el.innerHTML = '';
  typeKeys.forEach(t => {
    const o = document.createElement('option');
    o.value = t;
    o.textContent = typeLabels[t] || t;
    el.appendChild(o);
  });
  if (current && [...el.options].some(o => o.value === current)) {
    el.value = current;
  }
}

function clearFilters(prefix) {
  const type = document.getElementById('filter-' + prefix + '-type');
  const cat = document.getElementById('filter-' + prefix + '-category');
  const skill = document.getElementById('filter-' + prefix + '-skill');
  const ip = document.getElementById('filter-' + prefix + '-ip');
  const status = document.getElementById('filter-' + prefix + '-status');
  if (type) type.value = '';
  if (cat) cat.value = '';
  if (skill) skill.value = '';
  if (ip) ip.value = '';
  if (status) status.value = '';
  pageState[prefix].offset = 0;
  if (prefix === 'url') loadApprovals();
  if (prefix === 'image') loadImages();
  if (prefix === 'package') loadPackages();
  if (prefix === 'library') loadLibraries();
}

// Build query string for server-side filtered + paginated requests.
function buildFilterQuery(prefix) {
  const filter = prefix === 'package' || prefix === 'library' ? getTypedFilter(prefix) : getFilter(prefix);
  const ps = pageState[prefix];
  const params = new URLSearchParams();
  if (filter.status) params.set('status', filter.status);
  if (filter.category) params.set('category', filter.category);
  if (filter.skillID) params.set('skill_id', filter.skillID);
  if (filter.ip) params.set('source_ip', filter.ip);
  if (filter.type) params.set('type', filter.type);
  params.set('offset', ps.offset);
  params.set('limit', PAGE_SIZE);
  return params.toString();
}

// Render pagination controls.
function renderPager(prefix) {
  const pager = document.getElementById('pager-' + prefix);
  if (!pager) return;
  const ps = pageState[prefix];
  if (ps.total <= PAGE_SIZE) {
    pager.style.display = 'none';
    return;
  }
  pager.style.display = 'flex';
  const page = Math.floor(ps.offset / PAGE_SIZE) + 1;
  const totalPages = Math.ceil(ps.total / PAGE_SIZE);
  const prevDisabled = ps.offset === 0 ? 'disabled' : '';
  const nextDisabled = ps.offset + PAGE_SIZE >= ps.total ? 'disabled' : '';
  pager.innerHTML = `<span>Showing ${ps.offset + 1}-${Math.min(ps.offset + PAGE_SIZE, ps.total)} of ${ps.total}</span>
    <div class="pager-buttons">
      <button ${prevDisabled} onclick="goPage('${prefix}',-1)">Previous</button>
      <span style="padding:4px 8px">Page ${page} of ${totalPages}</span>
      <button ${nextDisabled} onclick="goPage('${prefix}',1)">Next</button>
    </div>`;
}

function goPage(prefix, dir) {
  const ps = pageState[prefix];
  ps.offset += dir * PAGE_SIZE;
  if (ps.offset < 0) ps.offset = 0;
  const loaders = { url: loadApprovals, image: loadImages, package: loadPackages, library: loadLibraries };
  loaders[prefix]();
}

// Reset page offset when filter changes.
function onFilterChange(prefix) {
  pageState[prefix].offset = 0;
  const loaders = { url: loadApprovals, image: loadImages, package: loadPackages, library: loadLibraries };
  loaders[prefix]();
}

// --- Selection & Bulk Actions ---

function approvalKey(a) {
  return (a.host||'') + '|' + (a.skill_id||'') + '|' + (a.source_ip||'') + '|' + (a.path_prefix||'');
}

function imgKey(a) {
  return (a.host||'') + '|' + (a.skill_id||'') + '|' + (a.source_ip||'');
}

function getSelectionSet(prefix) {
  if (prefix === 'url') return selectedApprovals;
  if (prefix === 'image') return selectedImages;
  if (prefix === 'package') return selectedPackages;
  return selectedLibraries;
}

function getCurrentFiltered(prefix) {
  if (prefix === 'url') return currentFilteredApprovals;
  if (prefix === 'image') return currentFilteredImages;
  if (prefix === 'package') return currentFilteredPackages;
  return currentFilteredLibraries;
}

function getKeyFn(prefix) {
  return prefix === 'url' ? approvalKey : imgKey;
}

function toggleSelect(prefix, el) {
  const key = el.getAttribute('data-key');
  if (!key) return;
  const set = getSelectionSet(prefix);
  if (el.checked) set.add(key);
  else set.delete(key);
  updateBulkBar(prefix);
}

function toggleSelectAll(prefix) {
  const allCb = document.getElementById('select-all-' + prefix);
  if (!allCb) return;
  const items = getCurrentFiltered(prefix);
  const set = getSelectionSet(prefix);
  const keyFn = getKeyFn(prefix);
  if (allCb.checked) {
    items.forEach(a => set.add(keyFn(a)));
  } else {
    items.forEach(a => set.delete(keyFn(a)));
  }
  const tbodyMap = { url: 'approvals-tbody', image: 'images-tbody', package: 'packages-tbody', library: 'libraries-tbody' };
  const tbody = document.getElementById(tbodyMap[prefix]);
  if (tbody) tbody.querySelectorAll('.row-cb').forEach(cb => { cb.checked = allCb.checked; });
  updateBulkBar(prefix);
}

function updateBulkBar(prefix) {
  const bar = document.getElementById('bulk-bar-' + prefix);
  if (!bar) return;
  const set = getSelectionSet(prefix);
  const count = set.size;
  bar.style.display = count > 0 ? 'flex' : 'none';
  const countEl = bar.querySelector('.bulk-count');
  if (countEl) countEl.textContent = count + ' item' + (count !== 1 ? 's' : '') + ' selected';
  const allCb = document.getElementById('select-all-' + prefix);
  const items = getCurrentFiltered(prefix);
  if (allCb) {
    if (items.length === 0) {
      allCb.checked = false;
      allCb.indeterminate = false;
    } else {
      const keyFn = getKeyFn(prefix);
      const selectedInFiltered = items.filter(a => set.has(keyFn(a))).length;
      allCb.checked = selectedInFiltered === items.length;
      allCb.indeterminate = selectedInFiltered > 0 && selectedInFiltered < items.length;
    }
  }
}

function clearSelection(prefix) {
  const set = getSelectionSet(prefix);
  set.clear();
  const allCb = document.getElementById('select-all-' + prefix);
  if (allCb) { allCb.checked = false; allCb.indeterminate = false; }
  const tbodyMap = { url: 'approvals-tbody', image: 'images-tbody', package: 'packages-tbody', library: 'libraries-tbody' };
  const tbody = document.getElementById(tbodyMap[prefix]);
  if (tbody) tbody.querySelectorAll('.row-cb').forEach(cb => { cb.checked = false; });
  updateBulkBar(prefix);
}

async function bulkAction(prefix, action) {
  const set = getSelectionSet(prefix);
  if (set.size === 0) return;
  const items = getCurrentFiltered(prefix);
  const keyFn = getKeyFn(prefix);
  const selectedItems = items.filter(a => set.has(keyFn(a)));
  const apiDecide = { url: '/api/approvals/decide', image: '/api/images/decide', package: '/api/packages/decide', library: '/api/libraries/decide' }[prefix];
  const apiDelete = { url: '/api/approvals', image: '/api/images', package: '/api/packages', library: '/api/libraries' }[prefix];
  if (action === 'promote') {
    const applicable = selectedItems.filter(a => a.source_ip && !a.skill_id);
    if (applicable.length === 0) {
      alert('No VM-specific items selected. Only items with a source IP and no skill can be promoted to global.');
      return;
    }
    const skip = selectedItems.length - applicable.length;
    const msg = skip > 0
      ? `Promote ${applicable.length} VM-specific item(s) to global? (${skip} item(s) will be skipped)`
      : `Promote ${applicable.length} item(s) to global?`;
    if (!confirm(msg)) return;
    try {
      for (const a of applicable) {
        const pp = prefix === 'url' ? (a.path_prefix || '') : '';
        const useStatus = (a.status !== 'pending' && a.status !== 'pending_timeout') ? a.status : 'approved';
        await api('POST', apiDecide, { host: a.host, skill_id: '', source_ip: '', path_prefix: pp, status: useStatus });
        await api('DELETE', apiDelete, { host: a.host, skill_id: a.skill_id || '', source_ip: a.source_ip, path_prefix: pp });
      }
    } catch (e) { alert('Error: ' + e.message); return; }
  } else {
    const actionLabel = action === 'approve' ? 'Approve' : action === 'deny' ? 'Deny' : 'Delete';
    if (!confirm(`${actionLabel} ${selectedItems.length} selected item(s)?`)) return;
    try {
      for (const a of selectedItems) {
        const pp = prefix === 'url' ? (a.path_prefix || '') : '';
        if (action === 'delete') {
          await api('DELETE', apiDelete, { host: a.host, skill_id: a.skill_id || '', source_ip: a.source_ip || '', path_prefix: pp });
        } else {
          await api('POST', apiDecide, { host: a.host, skill_id: a.skill_id || '', source_ip: a.source_ip || '', path_prefix: pp, status: action === 'approve' ? 'approved' : 'denied' });
        }
      }
    } catch (e) { alert('Error: ' + e.message); return; }
  }
  set.clear();
  const activePage = document.querySelector('.page.active');
  if (activePage) navigate(activePage.id.replace('page-', ''));
}

function formatCategory(category) {
  if (!category) return '<span class="badge-status" style="opacity:0.4">-</span>';
  return '<span class="category-badge">' + esc(category) + '</span>';
}

// Populate a <select> dropdown, preserving the current selection if still valid.
function populateSelect(selectId, options, emptyLabel) {
  const el = document.getElementById(selectId);
  if (!el) return;
  const current = el.value;
  el.innerHTML = '<option value="">' + esc(emptyLabel) + '</option>';
  options.forEach(opt => {
    const o = document.createElement('option');
    o.value = opt.value;
    o.textContent = opt.label;
    el.appendChild(o);
  });
  // Restore selection if still available.
  if (current && [...el.options].some(o => o.value === current)) {
    el.value = current;
  }
}

// Build filter dropdown options from data.
function populateFilterDropdowns(prefix, items) {
  // Categories from managed list.
  populateSelect('filter-' + prefix + '-category', currentCategories.map(c => ({ value: c, label: c })), 'All categories');

  // Skills from cached skills list (show name, value is ID).
  const skillIDs = [...new Set(items.map(a => a.skill_id).filter(Boolean))];
  const skillOpts = skillIDs.map(id => ({ value: id, label: skillNameByID(id) }));
  skillOpts.sort((a, b) => a.label.localeCompare(b.label));
  populateSelect('filter-' + prefix + '-skill', skillOpts, 'All skills');

  // Source IPs learned from the data.
  const ips = [...new Set(items.map(a => a.source_ip).filter(Boolean))].sort();
  populateSelect('filter-' + prefix + '-ip', ips.map(ip => ({ value: ip, label: ip })), 'All source IPs');
}

// Populate a category <select> in a modal.
function populateCategorySelect(selectId, selectedValue) {
  const el = document.getElementById(selectId);
  if (!el) return;
  el.innerHTML = '<option value="">No category</option>';
  currentCategories.forEach(c => {
    const o = document.createElement('option');
    o.value = c;
    o.textContent = c;
    el.appendChild(o);
  });
  el.value = selectedValue || '';
}

async function refreshCategories() {
  try {
    currentCategories = await api('GET', '/api/categories') || [];
  } catch (e) {
    currentCategories = [];
  }
}

async function refreshSkills() {
  try {
    currentSkills = await api('GET', '/api/skills') || [];
  } catch (e) {
    currentSkills = [];
  }
}

// --- URL Rules (Approvals) ---
async function loadApprovals() {
  try {
    const query = buildFilterQuery('url');
    const [result, meta] = await Promise.all([
      api('GET', '/api/approvals?' + query),
      api('GET', '/api/approvals/meta'),
      refreshSkills(),
    ]);
    const items = result.items || [];
    const total = result.total || 0;
    pageState.url.total = total;
    currentApprovals = items;
    currentFilteredApprovals = items;
    // Populate filter dropdowns from meta (not from full data).
    currentCategories = meta.categories || [];
    populateSelect('filter-url-category', currentCategories.map(c => ({ value: c, label: c })), 'All categories');
    const skillOpts = (meta.skill_ids || []).map(id => ({ value: id, label: skillNameByID(id) }));
    skillOpts.sort((a, b) => a.label.localeCompare(b.label));
    populateSelect('filter-url-skill', skillOpts, 'All skills');
    populateSelect('filter-url-ip', (meta.source_ips || []).map(ip => ({ value: ip, label: ip })), 'All source IPs');
    const tbody = document.getElementById('approvals-tbody');
    const rows = [];
    if (items.length === 0) {
      rows.push('<tr><td colspan="10" class="empty-state">No URL rules</td></tr>');
    } else {
      items.forEach((a, i) => {
        const key = approvalKey(a);
        const cbChecked = selectedApprovals.has(key) ? 'checked' : '';
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const pathDisplay = formatPathPrefix(a.path_prefix);
        const categoryDisplay = formatCategory(a.category);
        const pp = a.path_prefix || '';
        const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditRule(${i})" title="Edit rule">Edit</button>`;
        const deleteBtn = `<button class="btn btn-danger btn-sm" onclick="deleteApproval('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}')" title="Delete rule">Delete</button>`;
        let actions = '';
        if (a.status === 'pending') {
          const vmBtn = a.source_ip
            ? `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','','${esc(a.source_ip)}','${esc(pp)}','approved')" title="Approve for this VM">VM</button>` : '';
          const globalBtn = (a.skill_id || a.source_ip)
            ? `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','','','${esc(pp)}','approved')" title="Approve for all agents">Global</button>` : '';
          actions = `<button class="btn btn-success btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','approved')">Approve</button>
             ${vmBtn} ${globalBtn}
             <button class="btn btn-danger btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','denied')">Deny</button>
             ${editBtn} ${deleteBtn}`;
        } else {
          const promoteBtn = a.source_ip && !a.skill_id
            ? `<button class="btn btn-outline btn-sm" onclick="promoteToGlobal('${esc(a.host)}','${esc(a.source_ip)}','${esc(pp)}','${a.status}')" title="Promote to global rule">Promote to Global</button>` : '';
          actions = `<button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','approved')">Approve</button>
             <button class="btn btn-outline btn-sm" onclick="decide('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','denied')">Deny</button>
             ${promoteBtn}
             ${editBtn} ${deleteBtn}`;
        }
        const logModeDisplay = a.logging_mode === 'full'
          ? '<span class="badge-status" style="background:rgba(99,102,241,0.15);color:var(--accent)">Full</span>'
          : '<span class="badge-status" style="opacity:0.4">Normal</span>';
        rows.push(`<tr>
          <td class="cb-col"><input type="checkbox" class="row-cb" data-key="${esc(key)}" ${cbChecked} onchange="toggleSelect('url',this)"></td>
          <td><strong>${esc(a.host)}</strong></td>
          <td>${pathDisplay}</td>
          <td>${categoryDisplay}</td>
          <td>${logModeDisplay}</td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td><span class="badge-status ${a.status}">${a.status}</span></td>
          <td>${timeAgo(a.updated_at)}</td>
          <td>${actions}</td>
        </tr>`);
      });
    }
    tbody.innerHTML = rows.join('');
    updateBulkBar('url');
    renderPager('url');
  } catch (e) {
    console.error('URL rules load error:', e);
  }
}

async function decide(host, skillID, sourceIP, pathPrefix, status) {
  try {
    await api('POST', '/api/approvals/decide', { host, skill_id: skillID, source_ip: sourceIP, path_prefix: pathPrefix, status });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteApproval(host, skillID, sourceIP, pathPrefix) {
  if (!confirm(`Delete rule for "${host}"?`)) return;
  try {
    await api('DELETE', '/api/approvals', { host, skill_id: skillID, source_ip: sourceIP, path_prefix: pathPrefix });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function promoteToGlobal(host, sourceIP, pathPrefix, status) {
  if (!confirm(`Promote "${host}" from VM ${sourceIP} to a global rule?`)) return;
  try {
    await api('POST', '/api/approvals/decide', { host, skill_id: '', source_ip: '', path_prefix: pathPrefix, status });
    await api('DELETE', '/api/approvals', { host, skill_id: '', source_ip: sourceIP, path_prefix: pathPrefix });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- URL Rule Modal ---
function showAddRule() {
  editingRule = null;
  document.getElementById('modal-rule-title').textContent = 'Add URL Rule';
  document.getElementById('modal-rule-submit').textContent = 'Add Rule';
  document.getElementById('rule-host').value = '';
  document.getElementById('rule-path-prefix').value = '';
  document.getElementById('rule-level').value = 'global';
  document.getElementById('rule-source-ip').value = '';
  document.getElementById('rule-skill-id').value = '';
  document.getElementById('rule-status').value = 'approved';
  populateCategorySelect('rule-category', '');
  document.getElementById('rule-logging-mode').value = 'normal';
  document.getElementById('rule-note').value = '';
  updateRuleFields();
  document.getElementById('modal-rule').classList.add('active');
}

function showEditRule(idx) {
  const a = currentApprovals[idx];
  if (!a) return;
  editingRule = { host: a.host, pathPrefix: a.path_prefix || '', skillID: a.skill_id || '', sourceIP: a.source_ip || '' };
  document.getElementById('modal-rule-title').textContent = 'Edit URL Rule';
  document.getElementById('modal-rule-submit').textContent = 'Save';
  document.getElementById('rule-host').value = a.host;
  document.getElementById('rule-path-prefix').value = a.path_prefix || '';
  if (a.skill_id) {
    document.getElementById('rule-level').value = 'skill';
    document.getElementById('rule-skill-id').value = a.skill_id;
    document.getElementById('rule-source-ip').value = a.source_ip || '';
  } else if (a.source_ip) {
    document.getElementById('rule-level').value = 'vm';
    document.getElementById('rule-source-ip').value = a.source_ip;
  } else {
    document.getElementById('rule-level').value = 'global';
  }
  document.getElementById('rule-status').value = a.status === 'pending' ? 'approved' : a.status;
  populateCategorySelect('rule-category', a.category || '');
  document.getElementById('rule-logging-mode').value = a.logging_mode || 'normal';
  document.getElementById('rule-note').value = a.note || '';
  updateRuleFields();
  document.getElementById('modal-rule').classList.add('active');
}

function hideAddRule() {
  document.getElementById('modal-rule').classList.remove('active');
  editingRule = null;
}

function updateRuleFields() {
  const level = document.getElementById('rule-level').value;
  document.getElementById('rule-vm-fields').style.display = (level === 'vm' || level === 'skill') ? 'block' : 'none';
  document.getElementById('rule-skill-fields').style.display = level === 'skill' ? 'block' : 'none';
}

async function submitRule() {
  const host = document.getElementById('rule-host').value.trim();
  if (!host) { alert('Host pattern is required'); return; }
  const pathPrefix = document.getElementById('rule-path-prefix').value.trim();
  const level = document.getElementById('rule-level').value;
  const status = document.getElementById('rule-status').value;
  const category = document.getElementById('rule-category').value.trim();
  const loggingMode = document.getElementById('rule-logging-mode').value;
  const note = document.getElementById('rule-note').value.trim();
  let sourceIP = '';
  let skillID = '';
  if (level === 'vm' || level === 'skill') {
    sourceIP = document.getElementById('rule-source-ip').value.trim();
  }
  if (level === 'skill') {
    skillID = document.getElementById('rule-skill-id').value.trim();
    if (!skillID) { alert('Skill ID is required for skill-specific rules'); return; }
  }
  if (level === 'vm' && !sourceIP) {
    alert('Source IP is required for VM-specific rules'); return;
  }
  try {
    // If editing and key fields changed, delete the old rule first.
    if (editingRule) {
      const keyChanged = editingRule.host !== host ||
        editingRule.pathPrefix !== pathPrefix ||
        editingRule.skillID !== skillID ||
        editingRule.sourceIP !== sourceIP;
      if (keyChanged) {
        await api('DELETE', '/api/approvals', {
          host: editingRule.host, skill_id: editingRule.skillID,
          source_ip: editingRule.sourceIP, path_prefix: editingRule.pathPrefix,
        });
      }
    }
    await api('POST', '/api/approvals/decide', { host, skill_id: skillID, source_ip: sourceIP, path_prefix: pathPrefix, category, logging_mode: loggingMode, status, note });
    hideAddRule();
    loadApprovals();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Images ---
async function loadImages() {
  try {
    const query = buildFilterQuery('image');
    const [result, meta] = await Promise.all([
      api('GET', '/api/images?' + query),
      api('GET', '/api/images/meta'),
      refreshSkills(),
    ]);
    const items = result.items || [];
    pageState.image.total = result.total || 0;
    currentImages = items;
    currentFilteredImages = items;
    currentCategories = meta.categories || [];
    populateSelect('filter-image-category', currentCategories.map(c => ({ value: c, label: c })), 'All categories');
    const skillOpts = (meta.skill_ids || []).map(id => ({ value: id, label: skillNameByID(id) }));
    skillOpts.sort((a, b) => a.label.localeCompare(b.label));
    populateSelect('filter-image-skill', skillOpts, 'All skills');
    populateSelect('filter-image-ip', (meta.source_ips || []).map(ip => ({ value: ip, label: ip })), 'All source IPs');
    const tbody = document.getElementById('images-tbody');
    const rows = [];
    if (items.length === 0) {
      rows.push('<tr><td colspan="8" class="empty-state">No image approval records</td></tr>');
    } else {
      items.forEach((a, i) => {
        const key = imgKey(a);
        const cbChecked = selectedImages.has(key) ? 'checked' : '';
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const categoryDisplay = formatCategory(a.category);
        const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditImageRule(${i})" title="Edit rule">Edit</button>`;
        const deleteBtn = `<button class="btn btn-danger btn-sm" onclick="deleteImage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}')" title="Delete rule">Delete</button>`;
        let actions = '';
        if (a.status === 'pending') {
          const vmBtn = a.source_ip
            ? `<button class="btn btn-outline btn-sm" onclick="decideImage('${esc(a.host)}','','${esc(a.source_ip)}','approved')" title="Approve for this VM">VM</button>` : '';
          const globalBtn = (a.skill_id || a.source_ip)
            ? `<button class="btn btn-outline btn-sm" onclick="decideImage('${esc(a.host)}','','','approved')" title="Approve for all agents">Global</button>` : '';
          actions = `<button class="btn btn-success btn-sm" onclick="decideImage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             ${vmBtn} ${globalBtn}
             <button class="btn btn-danger btn-sm" onclick="decideImage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${editBtn} ${deleteBtn}`;
        } else {
          const promoteBtn = a.source_ip && !a.skill_id
            ? `<button class="btn btn-outline btn-sm" onclick="promoteImageToGlobal('${esc(a.host)}','${esc(a.source_ip)}','${a.status}')" title="Promote to global rule">Promote to Global</button>` : '';
          actions = `<button class="btn btn-outline btn-sm" onclick="decideImage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             <button class="btn btn-outline btn-sm" onclick="decideImage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${promoteBtn}
             ${editBtn} ${deleteBtn}`;
        }
        rows.push(`<tr>
          <td class="cb-col"><input type="checkbox" class="row-cb" data-key="${esc(key)}" ${cbChecked} onchange="toggleSelect('image',this)"></td>
          <td><strong>${esc(a.host)}</strong></td>
          <td>${categoryDisplay}</td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td><span class="badge-status ${a.status}">${a.status}</span></td>
          <td>${timeAgo(a.updated_at)}</td>
          <td>${actions}</td>
        </tr>`);
      });
    }
    tbody.innerHTML = rows.join('');
    updateBulkBar('image');
    renderPager('image');
  } catch (e) {
    console.error('Images load error:', e);
  }
}

async function decideImage(host, skillID, sourceIP, status) {
  try {
    await api('POST', '/api/images/decide', { host, skill_id: skillID, source_ip: sourceIP, status });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteImage(host, skillID, sourceIP) {
  if (!confirm(`Delete image rule for "${host}"?`)) return;
  try {
    await api('DELETE', '/api/images', { host, skill_id: skillID, source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function promoteImageToGlobal(host, sourceIP, status) {
  if (!confirm(`Promote "${host}" from VM ${sourceIP} to a global rule?`)) return;
  try {
    await api('POST', '/api/images/decide', { host, skill_id: '', source_ip: '', status });
    await api('DELETE', '/api/images', { host, skill_id: '', source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) {
      const pageId = activePage.id.replace('page-', '');
      navigate(pageId);
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Image Rule Modal ---
function showAddImageRule() {
  editingImageRule = null;
  document.getElementById('modal-image-title').textContent = 'Add Image Approval Rule';
  document.getElementById('modal-image-submit').textContent = 'Add Rule';
  document.getElementById('image-rule-host').value = '';
  document.getElementById('image-rule-level').value = 'global';
  document.getElementById('image-rule-source-ip').value = '';
  document.getElementById('image-rule-status').value = 'approved';
  populateCategorySelect('image-rule-category', '');
  document.getElementById('image-rule-note').value = '';
  updateImageRuleFields();
  document.getElementById('modal-image-rule').classList.add('active');
}

function showEditImageRule(idx) {
  const a = currentImages[idx];
  if (!a) return;
  editingImageRule = { host: a.host, skillID: a.skill_id || '', sourceIP: a.source_ip || '' };
  document.getElementById('modal-image-title').textContent = 'Edit Image Approval Rule';
  document.getElementById('modal-image-submit').textContent = 'Save';
  document.getElementById('image-rule-host').value = a.host;
  if (a.source_ip) {
    document.getElementById('image-rule-level').value = 'vm';
    document.getElementById('image-rule-source-ip').value = a.source_ip;
  } else {
    document.getElementById('image-rule-level').value = 'global';
  }
  document.getElementById('image-rule-status').value = a.status === 'pending' ? 'approved' : a.status;
  populateCategorySelect('image-rule-category', a.category || '');
  document.getElementById('image-rule-note').value = a.note || '';
  updateImageRuleFields();
  document.getElementById('modal-image-rule').classList.add('active');
}

function hideImageRuleModal() {
  document.getElementById('modal-image-rule').classList.remove('active');
  editingImageRule = null;
}

function updateImageRuleFields() {
  const level = document.getElementById('image-rule-level').value;
  document.getElementById('image-rule-vm-fields').style.display = level === 'vm' ? 'block' : 'none';
}

async function submitImageRule() {
  const host = document.getElementById('image-rule-host').value.trim();
  if (!host) { alert('Image pattern is required'); return; }
  const level = document.getElementById('image-rule-level').value;
  const status = document.getElementById('image-rule-status').value;
  const category = document.getElementById('image-rule-category').value.trim();
  const note = document.getElementById('image-rule-note').value.trim();
  let sourceIP = '';
  if (level === 'vm') {
    sourceIP = document.getElementById('image-rule-source-ip').value.trim();
    if (!sourceIP) { alert('Source IP is required for VM-specific rules'); return; }
  }
  try {
    if (editingImageRule) {
      const keyChanged = editingImageRule.host !== host ||
        editingImageRule.sourceIP !== sourceIP;
      if (keyChanged) {
        await api('DELETE', '/api/images', {
          host: editingImageRule.host, skill_id: editingImageRule.skillID,
          source_ip: editingImageRule.sourceIP,
        });
      }
    }
    await api('POST', '/api/images/decide', { host, skill_id: '', source_ip: sourceIP, category, status, note });
    hideImageRuleModal();
    loadImages();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- OS Packages ---
async function loadPackages() {
  try {
    const query = buildFilterQuery('package');
    const [result, meta] = await Promise.all([
      api('GET', '/api/packages?' + query),
      api('GET', '/api/packages/meta'),
      refreshSkills(),
    ]);
    const items = result.items || [];
    pageState.package.total = result.total || 0;
    currentPackages = items;
    currentFilteredPackages = items;
    currentCategories = meta.categories || [];
    populateSelect('filter-package-category', currentCategories.map(c => ({ value: c, label: c })), 'All categories');
    const skillOpts = (meta.skill_ids || []).map(id => ({ value: id, label: skillNameByID(id) }));
    skillOpts.sort((a, b) => a.label.localeCompare(b.label));
    populateSelect('filter-package-skill', skillOpts, 'All skills');
    populateSelect('filter-package-ip', (meta.source_ips || []).map(ip => ({ value: ip, label: ip })), 'All source IPs');
    const typeOpts = (meta.types || []).map(t => ({ value: t, label: typeLabels[t] || t }));
    populateSelect('filter-package-type', typeOpts, 'All types');
    const tbody = document.getElementById('packages-tbody');
    const rows = [];
    if (items.length === 0) {
      rows.push('<tr><td colspan="9" class="empty-state">No OS package approval records</td></tr>');
    } else {
      items.forEach((a, i) => {
        const key = imgKey(a);
        const cbChecked = selectedPackages.has(key) ? 'checked' : '';
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const categoryDisplay = formatCategory(a.category);
        const typeDisplay = formatLibraryType(a.host);
        const nameDisplay = formatLibraryName(a.host);
        const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditPackageRule(${i})" title="Edit rule">Edit</button>`;
        const deleteBtn = `<button class="btn btn-danger btn-sm" onclick="deletePackage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}')" title="Delete rule">Delete</button>`;
        let actions = '';
        if (a.status === 'pending') {
          const vmBtn = a.source_ip
            ? `<button class="btn btn-outline btn-sm" onclick="decidePackage('${esc(a.host)}','','${esc(a.source_ip)}','approved')" title="Approve for this VM">VM</button>` : '';
          const globalBtn = (a.skill_id || a.source_ip)
            ? `<button class="btn btn-outline btn-sm" onclick="decidePackage('${esc(a.host)}','','','approved')" title="Approve for all agents">Global</button>` : '';
          actions = `<button class="btn btn-success btn-sm" onclick="decidePackage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             ${vmBtn} ${globalBtn}
             <button class="btn btn-danger btn-sm" onclick="decidePackage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${editBtn} ${deleteBtn}`;
        } else {
          const promoteBtn = a.source_ip && !a.skill_id
            ? `<button class="btn btn-outline btn-sm" onclick="promotePackageToGlobal('${esc(a.host)}','${esc(a.source_ip)}','${a.status}')" title="Promote to global rule">Promote to Global</button>` : '';
          actions = `<button class="btn btn-outline btn-sm" onclick="decidePackage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             <button class="btn btn-outline btn-sm" onclick="decidePackage('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${promoteBtn}
             ${editBtn} ${deleteBtn}`;
        }
        rows.push(`<tr>
          <td class="cb-col"><input type="checkbox" class="row-cb" data-key="${esc(key)}" ${cbChecked} onchange="toggleSelect('package',this)"></td>
          <td><strong>${nameDisplay}</strong></td>
          <td>${typeDisplay}</td>
          <td>${categoryDisplay}</td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td><span class="badge-status ${a.status}">${a.status}</span></td>
          <td>${timeAgo(a.updated_at)}</td>
          <td>${actions}</td>
        </tr>`);
      });
    }
    tbody.innerHTML = rows.join('');
    updateBulkBar('package');
    renderPager('package');
  } catch (e) {
    console.error('Packages load error:', e);
  }
}

async function decidePackage(host, skillID, sourceIP, status) {
  try {
    await api('POST', '/api/packages/decide', { host, skill_id: skillID, source_ip: sourceIP, status });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

async function deletePackage(host, skillID, sourceIP) {
  if (!confirm(`Delete package rule for "${getLibraryName(host)}"?`)) return;
  try {
    await api('DELETE', '/api/packages', { host, skill_id: skillID, source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

async function promotePackageToGlobal(host, sourceIP, status) {
  if (!confirm(`Promote "${getLibraryName(host)}" from VM ${sourceIP} to a global rule?`)) return;
  try {
    await api('POST', '/api/packages/decide', { host, skill_id: '', source_ip: '', status });
    await api('DELETE', '/api/packages', { host, skill_id: '', source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

// --- Package Rule Modal ---
function showAddPackageRule() {
  editingPackageRule = null;
  document.getElementById('modal-package-title').textContent = 'Add OS Package Rule';
  document.getElementById('modal-package-submit').textContent = 'Add Rule';
  const pkgTypes = [...new Set(currentPackages.map(a => getLibraryType(a.host)).filter(Boolean))].sort();
  populateTypeSelect('package-rule-type', pkgTypes.length > 0 ? pkgTypes : Object.keys(typeLabels).filter(t => ['debian','alpine','ubuntu'].includes(t)));
  document.getElementById('package-rule-host').value = '';
  document.getElementById('package-rule-level').value = 'global';
  document.getElementById('package-rule-source-ip').value = '';
  document.getElementById('package-rule-status').value = 'approved';
  populateCategorySelect('package-rule-category', '');
  document.getElementById('package-rule-note').value = '';
  updatePackageRuleFields();
  document.getElementById('modal-package-rule').classList.add('active');
}

function showEditPackageRule(idx) {
  const a = currentPackages[idx];
  if (!a) return;
  editingPackageRule = { host: a.host, skillID: a.skill_id || '', sourceIP: a.source_ip || '' };
  document.getElementById('modal-package-title').textContent = 'Edit OS Package Rule';
  document.getElementById('modal-package-submit').textContent = 'Save';
  const pkgTypes = [...new Set(currentPackages.map(x => getLibraryType(x.host)).filter(Boolean))].sort();
  populateTypeSelect('package-rule-type', pkgTypes.length > 0 ? pkgTypes : Object.keys(typeLabels).filter(t => ['debian','alpine','ubuntu'].includes(t)));
  document.getElementById('package-rule-type').value = getLibraryType(a.host);
  document.getElementById('package-rule-host').value = getLibraryName(a.host);
  if (a.source_ip) {
    document.getElementById('package-rule-level').value = 'vm';
    document.getElementById('package-rule-source-ip').value = a.source_ip;
  } else {
    document.getElementById('package-rule-level').value = 'global';
  }
  document.getElementById('package-rule-status').value = a.status === 'pending' ? 'approved' : a.status;
  populateCategorySelect('package-rule-category', a.category || '');
  document.getElementById('package-rule-note').value = a.note || '';
  updatePackageRuleFields();
  document.getElementById('modal-package-rule').classList.add('active');
}

function hidePackageRuleModal() {
  document.getElementById('modal-package-rule').classList.remove('active');
  editingPackageRule = null;
}

function updatePackageRuleFields() {
  const level = document.getElementById('package-rule-level').value;
  document.getElementById('package-rule-vm-fields').style.display = level === 'vm' ? 'block' : 'none';
}

async function submitPackageRule() {
  const name = document.getElementById('package-rule-host').value.trim();
  if (!name) { alert('Package name is required'); return; }
  const type = document.getElementById('package-rule-type').value;
  const host = type + ':' + name;
  const level = document.getElementById('package-rule-level').value;
  const status = document.getElementById('package-rule-status').value;
  const category = document.getElementById('package-rule-category').value.trim();
  const note = document.getElementById('package-rule-note').value.trim();
  let sourceIP = '';
  if (level === 'vm') {
    sourceIP = document.getElementById('package-rule-source-ip').value.trim();
    if (!sourceIP) { alert('Source IP is required for VM-specific rules'); return; }
  }
  try {
    if (editingPackageRule) {
      const keyChanged = editingPackageRule.host !== host || editingPackageRule.sourceIP !== sourceIP;
      if (keyChanged) {
        await api('DELETE', '/api/packages', { host: editingPackageRule.host, skill_id: editingPackageRule.skillID, source_ip: editingPackageRule.sourceIP });
      }
    }
    await api('POST', '/api/packages/decide', { host, skill_id: '', source_ip: sourceIP, category, status, note });
    hidePackageRuleModal();
    loadPackages();
  } catch (e) { alert('Error: ' + e.message); }
}

// --- Code Libraries ---
async function loadLibraries() {
  try {
    const query = buildFilterQuery('library');
    const [result, meta] = await Promise.all([
      api('GET', '/api/libraries?' + query),
      api('GET', '/api/libraries/meta'),
      refreshSkills(),
    ]);
    const items = result.items || [];
    pageState.library.total = result.total || 0;
    currentLibraries = items;
    currentFilteredLibraries = items;
    currentCategories = meta.categories || [];
    populateSelect('filter-library-category', currentCategories.map(c => ({ value: c, label: c })), 'All categories');
    const skillOpts = (meta.skill_ids || []).map(id => ({ value: id, label: skillNameByID(id) }));
    skillOpts.sort((a, b) => a.label.localeCompare(b.label));
    populateSelect('filter-library-skill', skillOpts, 'All skills');
    populateSelect('filter-library-ip', (meta.source_ips || []).map(ip => ({ value: ip, label: ip })), 'All source IPs');
    const typeOpts = (meta.types || []).map(t => ({ value: t, label: typeLabels[t] || t }));
    populateSelect('filter-library-type', typeOpts, 'All types');
    const tbody = document.getElementById('libraries-tbody');
    const rows = [];
    if (items.length === 0) {
      rows.push('<tr><td colspan="9" class="empty-state">No code library approval records</td></tr>');
    } else {
      items.forEach((a, i) => {
        const key = imgKey(a);
        const cbChecked = selectedLibraries.has(key) ? 'checked' : '';
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const categoryDisplay = formatCategory(a.category);
        const typeDisplay = formatLibraryType(a.host);
        const nameDisplay = formatLibraryName(a.host);
        const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditLibraryRule(${i})" title="Edit rule">Edit</button>`;
        const deleteBtn = `<button class="btn btn-danger btn-sm" onclick="deleteLibrary('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}')" title="Delete rule">Delete</button>`;
        let actions = '';
        if (a.status === 'pending') {
          const vmBtn = a.source_ip
            ? `<button class="btn btn-outline btn-sm" onclick="decideLibrary('${esc(a.host)}','','${esc(a.source_ip)}','approved')" title="Approve for this VM">VM</button>` : '';
          const globalBtn = (a.skill_id || a.source_ip)
            ? `<button class="btn btn-outline btn-sm" onclick="decideLibrary('${esc(a.host)}','','','approved')" title="Approve for all agents">Global</button>` : '';
          actions = `<button class="btn btn-success btn-sm" onclick="decideLibrary('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             ${vmBtn} ${globalBtn}
             <button class="btn btn-danger btn-sm" onclick="decideLibrary('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${editBtn} ${deleteBtn}`;
        } else {
          const promoteBtn = a.source_ip && !a.skill_id
            ? `<button class="btn btn-outline btn-sm" onclick="promoteLibraryToGlobal('${esc(a.host)}','${esc(a.source_ip)}','${a.status}')" title="Promote to global rule">Promote to Global</button>` : '';
          actions = `<button class="btn btn-outline btn-sm" onclick="decideLibrary('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','approved')">Approve</button>
             <button class="btn btn-outline btn-sm" onclick="decideLibrary('${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','denied')">Deny</button>
             ${promoteBtn}
             ${editBtn} ${deleteBtn}`;
        }
        rows.push(`<tr>
          <td class="cb-col"><input type="checkbox" class="row-cb" data-key="${esc(key)}" ${cbChecked} onchange="toggleSelect('library',this)"></td>
          <td><strong>${nameDisplay}</strong></td>
          <td>${typeDisplay}</td>
          <td>${categoryDisplay}</td>
          <td>${skillDisplay}</td>
          <td>${sourceDisplay}</td>
          <td><span class="badge-status ${a.status}">${a.status}</span></td>
          <td>${timeAgo(a.updated_at)}</td>
          <td>${actions}</td>
        </tr>`);
      });
    }
    tbody.innerHTML = rows.join('');
    updateBulkBar('library');
    renderPager('library');
  } catch (e) {
    console.error('Libraries load error:', e);
  }
}

async function decideLibrary(host, skillID, sourceIP, status) {
  try {
    await api('POST', '/api/libraries/decide', { host, skill_id: skillID, source_ip: sourceIP, status });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

async function deleteLibrary(host, skillID, sourceIP) {
  if (!confirm(`Delete library rule for "${getLibraryName(host)}"?`)) return;
  try {
    await api('DELETE', '/api/libraries', { host, skill_id: skillID, source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

async function promoteLibraryToGlobal(host, sourceIP, status) {
  if (!confirm(`Promote "${getLibraryName(host)}" from VM ${sourceIP} to a global rule?`)) return;
  try {
    await api('POST', '/api/libraries/decide', { host, skill_id: '', source_ip: '', status });
    await api('DELETE', '/api/libraries', { host, skill_id: '', source_ip: sourceIP });
    const activePage = document.querySelector('.page.active');
    if (activePage) navigate(activePage.id.replace('page-', ''));
  } catch (e) { alert('Error: ' + e.message); }
}

// --- Library Rule Modal ---
function showAddLibraryRule() {
  editingLibraryRule = null;
  document.getElementById('modal-library-title').textContent = 'Add Code Library Rule';
  document.getElementById('modal-library-submit').textContent = 'Add Rule';
  const libTypes = [...new Set(currentLibraries.map(a => getLibraryType(a.host)).filter(Boolean))].sort();
  populateTypeSelect('library-rule-type', libTypes.length > 0 ? libTypes : Object.keys(typeLabels).filter(t => !['debian','alpine','ubuntu'].includes(t)));
  document.getElementById('library-rule-name').value = '';
  document.getElementById('library-rule-level').value = 'global';
  document.getElementById('library-rule-source-ip').value = '';
  document.getElementById('library-rule-status').value = 'approved';
  populateCategorySelect('library-rule-category', '');
  document.getElementById('library-rule-note').value = '';
  updateLibraryRuleFields();
  document.getElementById('modal-library-rule').classList.add('active');
}

function showEditLibraryRule(idx) {
  const a = currentLibraries[idx];
  if (!a) return;
  editingLibraryRule = { host: a.host, skillID: a.skill_id || '', sourceIP: a.source_ip || '' };
  document.getElementById('modal-library-title').textContent = 'Edit Code Library Rule';
  document.getElementById('modal-library-submit').textContent = 'Save';
  const libTypes = [...new Set(currentLibraries.map(x => getLibraryType(x.host)).filter(Boolean))].sort();
  populateTypeSelect('library-rule-type', libTypes.length > 0 ? libTypes : Object.keys(typeLabels).filter(t => !['debian','alpine','ubuntu'].includes(t)));
  document.getElementById('library-rule-type').value = getLibraryType(a.host);
  document.getElementById('library-rule-name').value = getLibraryName(a.host);
  if (a.source_ip) {
    document.getElementById('library-rule-level').value = 'vm';
    document.getElementById('library-rule-source-ip').value = a.source_ip;
  } else {
    document.getElementById('library-rule-level').value = 'global';
  }
  document.getElementById('library-rule-status').value = a.status === 'pending' ? 'approved' : a.status;
  populateCategorySelect('library-rule-category', a.category || '');
  document.getElementById('library-rule-note').value = a.note || '';
  updateLibraryRuleFields();
  document.getElementById('modal-library-rule').classList.add('active');
}

function hideLibraryRuleModal() {
  document.getElementById('modal-library-rule').classList.remove('active');
  editingLibraryRule = null;
}

function updateLibraryRuleFields() {
  const level = document.getElementById('library-rule-level').value;
  document.getElementById('library-rule-vm-fields').style.display = level === 'vm' ? 'block' : 'none';
}

async function submitLibraryRule() {
  const type = document.getElementById('library-rule-type').value;
  const name = document.getElementById('library-rule-name').value.trim();
  if (!name) { alert('Library name is required'); return; }
  const host = type + ':' + name;
  const level = document.getElementById('library-rule-level').value;
  const status = document.getElementById('library-rule-status').value;
  const category = document.getElementById('library-rule-category').value.trim();
  const note = document.getElementById('library-rule-note').value.trim();
  let sourceIP = '';
  if (level === 'vm') {
    sourceIP = document.getElementById('library-rule-source-ip').value.trim();
    if (!sourceIP) { alert('Source IP is required for VM-specific rules'); return; }
  }
  try {
    if (editingLibraryRule) {
      const keyChanged = editingLibraryRule.host !== host || editingLibraryRule.sourceIP !== sourceIP;
      if (keyChanged) {
        await api('DELETE', '/api/libraries', { host: editingLibraryRule.host, skill_id: editingLibraryRule.skillID, source_ip: editingLibraryRule.sourceIP });
      }
    }
    await api('POST', '/api/libraries/decide', { host, skill_id: '', source_ip: sourceIP, category, status, note });
    hideLibraryRuleModal();
    loadLibraries();
  } catch (e) { alert('Error: ' + e.message); }
}

// --- Skills ---
async function loadSkills() {
  try {
    const skills = await api('GET', '/api/skills');
    currentSkills = skills || [];
    currentSkills.sort((a, b) => a.name.localeCompare(b.name));
    const tbody = document.getElementById('skills-tbody');
    tbody.innerHTML = '';
    if (currentSkills.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No skills configured. Create one to get started.</td></tr>';
      return;
    }
    currentSkills.forEach((s, idx) => {
      const desc = s.description ? esc(s.description).substring(0, 120) + (s.description.length > 120 ? '...' : '') : '<span class="muted">none</span>';
      tbody.innerHTML += `<tr>
        <td><strong>${esc(s.name)}</strong></td>
        <td>${desc}</td>
        <td><span class="badge-status ${s.active ? 'approved' : 'denied'}">${s.active ? 'active' : 'inactive'}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="showEditSkill(${idx})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteSkill('${esc(s.id)}','${esc(s.name)}')">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Skills load error:', e);
  }
}

function showCreateSkill() {
  editingSkillID = null;
  document.getElementById('modal-skill-title').textContent = 'Create Skill';
  document.getElementById('modal-skill-submit').textContent = 'Create';
  document.getElementById('skill-name').value = '';
  document.getElementById('skill-description').value = '';
  document.getElementById('skill-active-group').style.display = 'none';
  document.getElementById('modal-skill').classList.add('active');
}

function showEditSkill(idx) {
  const s = currentSkills[idx];
  if (!s) return;
  editingSkillID = s.id;
  document.getElementById('modal-skill-title').textContent = 'Edit Skill';
  document.getElementById('modal-skill-submit').textContent = 'Save';
  document.getElementById('skill-name').value = s.name;
  document.getElementById('skill-description').value = s.description || '';
  document.getElementById('skill-active-group').style.display = 'block';
  document.getElementById('skill-active').value = s.active ? 'true' : 'false';
  document.getElementById('modal-skill').classList.add('active');
}

function hideSkillModal() {
  document.getElementById('modal-skill').classList.remove('active');
  editingSkillID = null;
  // Reset to Write tab.
  switchSkillTab('write');
}

function switchSkillTab(tab) {
  const tabs = document.querySelectorAll('#modal-skill .md-tab');
  const textarea = document.getElementById('skill-description');
  const preview = document.getElementById('skill-description-preview');
  tabs.forEach(t => t.classList.remove('active'));
  if (tab === 'preview') {
    tabs[1].classList.add('active');
    textarea.style.display = 'none';
    preview.style.display = 'block';
    preview.innerHTML = renderMarkdown(textarea.value);
  } else {
    tabs[0].classList.add('active');
    textarea.style.display = '';
    preview.style.display = 'none';
  }
}

// Lightweight GitHub-flavored Markdown renderer.
function renderMarkdown(src) {
  if (!src) return '<p style="color:var(--text-dim)">Nothing to preview</p>';
  let html = '';
  // Escape HTML first.
  src = src.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  // Fenced code blocks.
  src = src.replace(/```(\w*)\n([\s\S]*?)```/g, function(_, lang, code) {
    return '\x00PRE' + lang + '\x00' + code.replace(/\n$/, '') + '\x00/PRE\x00';
  });
  // Split into blocks by blank lines, preserving pre blocks.
  const blocks = [];
  let current = '';
  src.split('\n').forEach(line => {
    if (line.startsWith('\x00PRE')) {
      if (current.trim()) { blocks.push(current); current = ''; }
      current = line;
    } else if (current.startsWith('\x00PRE') && !current.includes('\x00/PRE\x00')) {
      current += '\n' + line;
    } else if (current.startsWith('\x00PRE') && current.includes('\x00/PRE\x00')) {
      blocks.push(current);
      current = line;
    } else if (line.trim() === '') {
      if (current.trim()) { blocks.push(current); current = ''; }
    } else {
      current += (current ? '\n' : '') + line;
    }
  });
  if (current.trim()) blocks.push(current);

  for (const block of blocks) {
    // Fenced code block.
    if (block.startsWith('\x00PRE')) {
      const m = block.match(/\x00PRE(\w*)\x00([\s\S]*?)\x00\/PRE\x00/);
      if (m) { html += '<pre><code>' + m[2] + '</code></pre>'; continue; }
    }
    const lines = block.split('\n');
    // Heading.
    if (lines.length === 1 && /^#{1,6}\s/.test(lines[0])) {
      const m = lines[0].match(/^(#{1,6})\s+(.*)/);
      const level = m[1].length;
      html += '<h' + level + '>' + inlineMarkdown(m[2]) + '</h' + level + '>';
      continue;
    }
    // Horizontal rule.
    if (lines.length === 1 && /^(-{3,}|\*{3,}|_{3,})$/.test(lines[0].trim())) {
      html += '<hr>';
      continue;
    }
    // Table.
    if (lines.length >= 2 && lines[0].includes('|') && /^\|?[\s-:|]+\|?$/.test(lines[1])) {
      html += renderTable(lines);
      continue;
    }
    // Blockquote.
    if (lines[0].startsWith('&gt; ') || lines[0] === '&gt;') {
      const bqLines = lines.map(l => l.replace(/^&gt;\s?/, ''));
      html += '<blockquote>' + renderMarkdown(bqLines.join('\n').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')) + '</blockquote>';
      continue;
    }
    // Unordered list.
    if (/^[\s]*[-*+]\s/.test(lines[0])) {
      html += renderList(lines, 'ul');
      continue;
    }
    // Ordered list.
    if (/^[\s]*\d+\.\s/.test(lines[0])) {
      html += renderList(lines, 'ol');
      continue;
    }
    // Paragraph.
    html += '<p>' + lines.map(l => inlineMarkdown(l)).join('<br>') + '</p>';
  }
  return html;
}

function inlineMarkdown(s) {
  // Inline code.
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Images (before links).
  s = s.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img alt="$1" src="$2">');
  // Links.
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  // Bold+italic.
  s = s.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  // Bold.
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
  // Italic.
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/_(.+?)_/g, '<em>$1</em>');
  // Strikethrough.
  s = s.replace(/~~(.+?)~~/g, '<del>$1</del>');
  return s;
}

function renderList(lines, tag) {
  let html = '<' + tag + '>';
  for (const line of lines) {
    const text = line.replace(/^[\s]*[-*+]\s/, '').replace(/^[\s]*\d+\.\s/, '');
    html += '<li>' + inlineMarkdown(text) + '</li>';
  }
  html += '</' + tag + '>';
  return html;
}

function renderTable(lines) {
  // Parse alignment from separator row.
  const sepCells = lines[1].split('|').map(c => c.trim()).filter(c => c);
  const aligns = sepCells.map(c => {
    if (c.startsWith(':') && c.endsWith(':')) return 'center';
    if (c.endsWith(':')) return 'right';
    return 'left';
  });
  const parseRow = line => line.replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
  let html = '<table><thead><tr>';
  const headers = parseRow(lines[0]);
  headers.forEach((h, i) => {
    html += '<th style="text-align:' + (aligns[i] || 'left') + '">' + inlineMarkdown(h) + '</th>';
  });
  html += '</tr></thead><tbody>';
  for (let i = 2; i < lines.length; i++) {
    if (!lines[i].includes('|')) continue;
    html += '<tr>';
    const cells = parseRow(lines[i]);
    cells.forEach((c, j) => {
      html += '<td style="text-align:' + (aligns[j] || 'left') + '">' + inlineMarkdown(c) + '</td>';
    });
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

async function submitSkill() {
  if (editingSkillID) {
    await updateSkill();
  } else {
    await createSkill();
  }
}

async function createSkill() {
  const name = document.getElementById('skill-name').value.trim();
  const description = document.getElementById('skill-description').value.trim();
  if (!name) { alert('Name is required'); return; }
  try {
    await api('POST', '/api/skills', { name, description });
    hideSkillModal();
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function updateSkill() {
  const id = editingSkillID;
  const name = document.getElementById('skill-name').value.trim();
  const description = document.getElementById('skill-description').value.trim();
  const active = document.getElementById('skill-active').value === 'true';
  if (!name) { alert('Name is required'); return; }
  try {
    await api('PUT', '/api/skills', { id, name, description, active });
    hideSkillModal();
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteSkill(id, name) {
  if (!confirm(`Delete skill "${name}"?`)) return;
  try {
    await api('DELETE', '/api/skills?id=' + encodeURIComponent(id));
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Credentials ---
async function loadCredentials() {
  try {
    const creds = await api('GET', '/api/credentials');
    currentCredentials = creds || [];
    currentCredentials.sort((a, b) => a.name.localeCompare(b.name));
    const tbody = document.getElementById('credentials-tbody');
    tbody.innerHTML = '';
    if (currentCredentials.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No credentials configured.</td></tr>';
      return;
    }
    currentCredentials.forEach((c, idx) => {
      tbody.innerHTML += `<tr>
        <td><strong>${esc(c.name)}</strong></td>
        <td>${esc(c.host_pattern)}</td>
        <td>${c.source_ip ? esc(c.source_ip) : '<span class="muted">global</span>'}</td>
        <td><span class="badge-status approved">${esc(c.injection_type)}</span></td>
        <td><span class="badge-status ${c.active ? 'approved' : 'denied'}">${c.active ? 'active' : 'inactive'}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="showEditCred(${idx})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteCredential('${esc(c.id)}')">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Credentials load error:', e);
  }
  loadDatabases();
}

// --- Databases ---

const DB_PORT_DEFAULTS = { mssql: 1433, postgres: 5432, mysql: 3306 };

async function loadDatabases() {
  try {
    const dbs = await api('GET', '/api/databases');
    currentDatabases = dbs || [];
    currentDatabases.sort((a, b) => a.name.localeCompare(b.name));
    const tbody = document.getElementById('databases-tbody');
    tbody.innerHTML = '';
    if (currentDatabases.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No database connections configured.</td></tr>';
      return;
    }
    currentDatabases.forEach((db, idx) => {
      const driverLabel = { mssql: 'MSSQL', postgres: 'PostgreSQL', mysql: 'MySQL' }[db.driver] || db.driver;
      const hostPort = db.host + (db.port ? ':' + db.port : '');
      tbody.innerHTML += `<tr>
        <td><strong>${esc(db.name)}</strong></td>
        <td><code>/v1/db/${esc(db.api_path)}/query</code></td>
        <td><span class="badge-status approved">${esc(driverLabel)}</span></td>
        <td>${esc(hostPort)}</td>
        <td>${esc(db.db_name)}</td>
        <td>${db.source_ip ? esc(db.source_ip) : '<span class="muted">global</span>'}</td>
        <td><span class="badge-status ${db.active ? 'approved' : 'denied'}">${db.active ? 'active' : 'inactive'}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="showEditDB(${idx})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteDatabase('${esc(db.id)}','${esc(db.name)}')">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Databases load error:', e);
  }
}

function showCreateDB() {
  editingDBID = null;
  document.getElementById('modal-db-title').textContent = 'Add Database Connection';
  document.getElementById('modal-db-submit').textContent = 'Add';
  document.getElementById('db-name').value = '';
  document.getElementById('db-api-path').value = '';
  document.getElementById('db-driver').value = 'mssql';
  document.getElementById('db-host').value = '';
  document.getElementById('db-port').value = '';
  document.getElementById('db-port').placeholder = '1433';
  document.getElementById('db-dbname').value = '';
  document.getElementById('db-username').value = '';
  document.getElementById('db-password').value = '';
  document.getElementById('db-password').placeholder = 'password';
  document.getElementById('db-source-ip').value = '';
  document.getElementById('db-active-group').style.display = 'none';
  document.getElementById('modal-db').classList.add('active');
}

function showEditDB(idx) {
  const db = currentDatabases[idx];
  if (!db) return;
  editingDBID = db.id;
  document.getElementById('modal-db-title').textContent = 'Edit Database Connection';
  document.getElementById('modal-db-submit').textContent = 'Save';
  document.getElementById('db-name').value = db.name;
  document.getElementById('db-api-path').value = db.api_path;
  document.getElementById('db-driver').value = db.driver;
  document.getElementById('db-host').value = db.host;
  document.getElementById('db-port').value = db.port || '';
  document.getElementById('db-port').placeholder = DB_PORT_DEFAULTS[db.driver] || '';
  document.getElementById('db-dbname').value = db.db_name;
  document.getElementById('db-username').value = db.username;
  document.getElementById('db-password').value = '';
  document.getElementById('db-password').placeholder = 'leave empty to keep current value';
  document.getElementById('db-source-ip').value = db.source_ip || '';
  document.getElementById('db-active-group').style.display = 'block';
  document.getElementById('db-active').value = db.active ? 'true' : 'false';
  document.getElementById('modal-db').classList.add('active');
}

function hideDBModal() {
  document.getElementById('modal-db').classList.remove('active');
  editingDBID = null;
}

function updateDBDefaults() {
  const driver = document.getElementById('db-driver').value;
  document.getElementById('db-port').placeholder = DB_PORT_DEFAULTS[driver] || '';
}

async function submitDatabase() {
  const db = {
    name: document.getElementById('db-name').value.trim(),
    api_path: document.getElementById('db-api-path').value.trim(),
    driver: document.getElementById('db-driver').value,
    host: document.getElementById('db-host').value.trim(),
    port: parseInt(document.getElementById('db-port').value) || 0,
    db_name: document.getElementById('db-dbname').value.trim(),
    username: document.getElementById('db-username').value.trim(),
    password: document.getElementById('db-password').value,
    source_ip: document.getElementById('db-source-ip').value.trim(),
  };
  if (!db.name || !db.api_path || !db.host || !db.db_name) {
    alert('Name, API path, host, and database name are required');
    return;
  }
  // Validate API path: only alphanumeric, dash, underscore
  if (!/^[a-zA-Z0-9_-]+$/.test(db.api_path)) {
    alert('API path must contain only letters, numbers, dashes, and underscores');
    return;
  }
  try {
    if (editingDBID) {
      db.id = editingDBID;
      db.active = document.getElementById('db-active').value === 'true';
      await api('PUT', '/api/databases', db);
    } else {
      db.active = true;
      await api('POST', '/api/databases', db);
    }
    hideDBModal();
    loadDatabases();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteDatabase(id, name) {
  if (!confirm(`Delete database connection "${name}"?`)) return;
  try {
    await api('DELETE', '/api/databases?id=' + encodeURIComponent(id));
    loadDatabases();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function showCreateCred() {
  editingCredID = null;
  document.getElementById('modal-cred-title').textContent = 'Add Credential';
  document.getElementById('modal-cred-submit').textContent = 'Add';
  document.getElementById('cred-name').value = '';
  document.getElementById('cred-host').value = '';
  document.getElementById('cred-source-ip').value = '';
  document.getElementById('cred-type').value = 'header';
  document.getElementById('cred-header-name').value = '';
  document.getElementById('cred-header-value').value = '';
  document.getElementById('cred-header-value').placeholder = 'secret value';
  document.getElementById('cred-username').value = '';
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-password').placeholder = '';
  document.getElementById('cred-bearer-token').value = '';
  document.getElementById('cred-bearer-token').placeholder = '';
  document.getElementById('cred-param-name').value = '';
  document.getElementById('cred-param-value').value = '';
  document.getElementById('cred-param-value').placeholder = '';
  document.getElementById('cred-active-group').style.display = 'none';
  updateCredFields();
  document.getElementById('modal-cred').classList.add('active');
}

function showEditCred(idx) {
  const c = currentCredentials[idx];
  if (!c) return;
  editingCredID = c.id;
  document.getElementById('modal-cred-title').textContent = 'Edit Credential';
  document.getElementById('modal-cred-submit').textContent = 'Save';
  document.getElementById('cred-name').value = c.name;
  document.getElementById('cred-host').value = c.host_pattern;
  document.getElementById('cred-source-ip').value = c.source_ip || '';
  document.getElementById('cred-type').value = c.injection_type;
  // Non-secret fields
  document.getElementById('cred-header-name').value = c.header_name || '';
  document.getElementById('cred-username').value = c.username || '';
  document.getElementById('cred-param-name').value = c.param_name || '';
  // Secret fields: leave empty, show placeholder
  document.getElementById('cred-header-value').value = '';
  document.getElementById('cred-header-value').placeholder = 'leave empty to keep current value';
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-password').placeholder = 'leave empty to keep current value';
  document.getElementById('cred-bearer-token').value = '';
  document.getElementById('cred-bearer-token').placeholder = 'leave empty to keep current value';
  document.getElementById('cred-param-value').value = '';
  document.getElementById('cred-param-value').placeholder = 'leave empty to keep current value';
  // Show active toggle
  document.getElementById('cred-active-group').style.display = 'block';
  document.getElementById('cred-active').value = c.active ? 'true' : 'false';
  updateCredFields();
  document.getElementById('modal-cred').classList.add('active');
}

function hideCredModal() {
  document.getElementById('modal-cred').classList.remove('active');
  editingCredID = null;
}

function updateCredFields() {
  const type = document.getElementById('cred-type').value;
  document.getElementById('cred-header-fields').style.display = type === 'header' ? 'block' : 'none';
  document.getElementById('cred-basic-fields').style.display = type === 'basic_auth' ? 'block' : 'none';
  document.getElementById('cred-bearer-fields').style.display = type === 'bearer' ? 'block' : 'none';
  document.getElementById('cred-query-fields').style.display = type === 'query_param' ? 'block' : 'none';
}

async function submitCredential() {
  if (editingCredID) {
    await updateCredential();
  } else {
    await createCredential();
  }
}

async function createCredential() {
  const type = document.getElementById('cred-type').value;
  const cred = {
    name: document.getElementById('cred-name').value.trim(),
    host_pattern: document.getElementById('cred-host').value.trim(),
    source_ip: document.getElementById('cred-source-ip').value.trim(),
    injection_type: type,
    active: true,
  };
  if (!cred.name || !cred.host_pattern) { alert('Name and host pattern are required'); return; }
  if (type === 'header') {
    cred.header_name = document.getElementById('cred-header-name').value.trim();
    cred.header_value = document.getElementById('cred-header-value').value.trim();
  } else if (type === 'basic_auth') {
    cred.username = document.getElementById('cred-username').value.trim();
    cred.password = document.getElementById('cred-password').value.trim();
  } else if (type === 'bearer') {
    cred.token = document.getElementById('cred-bearer-token').value.trim();
  } else if (type === 'query_param') {
    cred.param_name = document.getElementById('cred-param-name').value.trim();
    cred.param_value = document.getElementById('cred-param-value').value.trim();
  }
  try {
    await api('POST', '/api/credentials', cred);
    hideCredModal();
    loadCredentials();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function updateCredential() {
  const type = document.getElementById('cred-type').value;
  const cred = {
    id: editingCredID,
    name: document.getElementById('cred-name').value.trim(),
    host_pattern: document.getElementById('cred-host').value.trim(),
    source_ip: document.getElementById('cred-source-ip').value.trim(),
    injection_type: type,
    active: document.getElementById('cred-active').value === 'true',
  };
  if (!cred.name || !cred.host_pattern) { alert('Name and host pattern are required'); return; }
  // Only send secret fields if user entered a new value (empty = keep current on backend).
  if (type === 'header') {
    cred.header_name = document.getElementById('cred-header-name').value.trim();
    cred.header_value = document.getElementById('cred-header-value').value;
  } else if (type === 'basic_auth') {
    cred.username = document.getElementById('cred-username').value.trim();
    cred.password = document.getElementById('cred-password').value;
  } else if (type === 'bearer') {
    cred.token = document.getElementById('cred-bearer-token').value;
  } else if (type === 'query_param') {
    cred.param_name = document.getElementById('cred-param-name').value.trim();
    cred.param_value = document.getElementById('cred-param-value').value;
  }
  try {
    await api('PUT', '/api/credentials', cred);
    hideCredModal();
    loadCredentials();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteCredential(id) {
  if (!confirm('Delete this credential?')) return;
  try {
    await api('DELETE', '/api/credentials?id=' + encodeURIComponent(id));
    loadCredentials();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Logs ---

function getCategoryForHost(host) {
  for (const a of currentApprovals) {
    if (!a.category) continue;
    if (a.host === host) return a.category;
    if (a.host.startsWith('*.') && host.endsWith(a.host.slice(1))) return a.category;
  }
  return '';
}

function getLogFilter() {
  return {
    skillID: document.getElementById('filter-log-skill')?.value || '',
    method: document.getElementById('filter-log-method')?.value || '',
    status: document.getElementById('filter-log-status')?.value || '',
    category: document.getElementById('filter-log-category')?.value || '',
  };
}

function matchesLogFilter(l, filter) {
  if (filter.skillID && (l.skill_id || '') !== filter.skillID) return false;
  if (filter.method && l.method !== filter.method) return false;
  if (filter.status && l.status !== filter.status) return false;
  if (filter.category && getCategoryForHost(l.host) !== filter.category) return false;
  return true;
}

function applyLogFilters() {
  renderLogs();
}

function clearLogFilters() {
  ['skill', 'method', 'status', 'category'].forEach(f => {
    const el = document.getElementById('filter-log-' + f);
    if (el) el.value = '';
  });
  renderLogs();
}

function populateLogFilterDropdowns(logs) {
  const skillIDs = [...new Set(logs.map(l => l.skill_id).filter(Boolean))];
  const skillOpts = skillIDs.map(id => ({ value: id, label: skillNameByID(id) }));
  skillOpts.sort((a, b) => a.label.localeCompare(b.label));
  populateSelect('filter-log-skill', skillOpts, 'All skills');

  const methods = [...new Set(logs.map(l => l.method).filter(Boolean))].sort();
  populateSelect('filter-log-method', methods.map(m => ({ value: m, label: m })), 'All methods');

  const cats = [...new Set(logs.map(l => getCategoryForHost(l.host)).filter(Boolean))].sort();
  populateSelect('filter-log-category', cats.map(c => ({ value: c, label: c })), 'All categories');
}

async function loadLogs() {
  try {
    const [logs] = await Promise.all([
      api('GET', '/api/logs?limit=200'),
      refreshSkills(),
      refreshCategories(),
    ]);
    currentLogs = logs || [];
    if (currentLogs.length > 0) lastLogID = currentLogs[0].id;
    populateLogFilterDropdowns(currentLogs);
    renderLogs();
  } catch (e) {
    console.error('Logs load error:', e);
  }
}

function renderLogs() {
  const filter = getLogFilter();
  const filtered = currentLogs.filter(l => matchesLogFilter(l, filter));
  const tbody = document.getElementById('logs-tbody');
  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No log entries yet</td></tr>';
    return;
  }
  filtered.forEach(l => {
    const detailBtn = l.has_full_log
      ? `<button class="btn btn-outline btn-sm" onclick="showLogDetail(${l.id})">Details</button>`
      : '';
    tbody.innerHTML += `<tr>
      <td style="color:var(--text-dim);font-size:11px">${formatTime(l.timestamp)}</td>
      <td>${formatSkillID(l.skill_id)}</td>
      <td><span class="method-badge">${esc(l.method)}</span></td>
      <td><strong>${esc(l.host)}</strong></td>
      <td>${esc(l.path || '-')}</td>
      <td><span class="badge-status ${l.status}">${l.status}</span></td>
      <td style="font-size:12px;color:var(--text-dim)">${esc(l.detail || '')}</td>
      <td>${detailBtn}</td>
    </tr>`;
  });
}

// --- Log Detail ---
async function showLogDetail(logId) {
  try {
    const detail = await api('GET', '/api/logs/detail?id=' + logId);
    const content = document.getElementById('log-detail-content');
    content.innerHTML = `
      <div style="margin-bottom:12px">
        <span class="method-badge">${esc(detail.method)}</span>
        <strong>${esc(detail.host)}</strong>${esc(detail.path || '')}
        <span class="badge-status ${detail.status}">${detail.status}</span>
      </div>
      <h4 style="margin:12px 0 6px;font-size:13px;color:var(--text-dim);text-transform:uppercase">Request Headers</h4>
      <pre class="detail-pre">${formatHeaders(detail.request_headers)}</pre>
      ${detail.request_body ? `<h4 style="margin:12px 0 6px;font-size:13px;color:var(--text-dim);text-transform:uppercase">Request Body</h4><pre class="detail-pre">${esc(detail.request_body)}</pre>` : ''}
      <h4 style="margin:12px 0 6px;font-size:13px;color:var(--text-dim);text-transform:uppercase">Response ${detail.response_status ? detail.response_status : ''} Headers</h4>
      <pre class="detail-pre">${formatHeaders(detail.response_headers)}</pre>
      ${detail.response_body ? `<h4 style="margin:12px 0 6px;font-size:13px;color:var(--text-dim);text-transform:uppercase">Response Body</h4><pre class="detail-pre">${esc(detail.response_body)}</pre>` : ''}
    `;
    document.getElementById('modal-log-detail').classList.add('active');
  } catch (e) {
    alert('Error loading details: ' + e.message);
  }
}

function hideLogDetail() {
  document.getElementById('modal-log-detail').classList.remove('active');
}

function formatHeaders(headers) {
  if (!headers || Object.keys(headers).length === 0) return '<span style="color:var(--text-dim)">(none)</span>';
  return Object.entries(headers).map(([k, vals]) =>
    vals.map(v => esc(k) + ': ' + esc(v)).join('\n')
  ).join('\n');
}

// --- Polling ---
let lastPendingCounts = { approvals: -1, images: -1, packages: -1, libraries: -1 };

function startPolling() {
  pollInterval = setInterval(async () => {
    try {
      // Use lightweight pending counts endpoint instead of fetching full lists.
      const counts = await api('GET', '/api/pending-counts');
      updateBadgeCount('approval-badge', counts.approvals || 0);
      updateBadgeCount('image-badge', counts.images || 0);
      updateBadgeCount('package-badge', counts.packages || 0);
      updateBadgeCount('library-badge', counts.libraries || 0);

      // Only refresh active page if pending counts changed.
      const changed = counts.approvals !== lastPendingCounts.approvals ||
        counts.images !== lastPendingCounts.images ||
        counts.packages !== lastPendingCounts.packages ||
        counts.libraries !== lastPendingCounts.libraries;
      lastPendingCounts = { ...counts };

      // Poll new logs
      if (document.getElementById('page-logs').classList.contains('active')) {
        const newLogs = await api('GET', '/api/logs?after=' + lastLogID);
        if (newLogs && newLogs.length > 0) {
          newLogs.forEach(l => { if (l.id > lastLogID) lastLogID = l.id; });
          currentLogs = [...[...newLogs].reverse(), ...currentLogs];
          populateLogFilterDropdowns(currentLogs);
          renderLogs();
        }
      }

      // Only refresh active rule pages if counts changed (new pending items arrived).
      if (changed) {
        if (document.getElementById('page-dashboard').classList.contains('active')) {
          loadDashboard();
        }
        if (document.getElementById('page-approvals').classList.contains('active')) {
          loadApprovals();
        }
        if (document.getElementById('page-images').classList.contains('active')) {
          loadImages();
        }
        if (document.getElementById('page-packages').classList.contains('active')) {
          loadPackages();
        }
        if (document.getElementById('page-libraries').classList.contains('active')) {
          loadLibraries();
        }
      }
    } catch (e) {
      // Silently ignore poll errors
    }
  }, 3000);
}

function updateBadgeCount(id, count) {
  const badge = document.getElementById(id);
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline';
  } else {
    badge.style.display = 'none';
  }
}

// --- Utilities ---
function esc(s) {
  if (!s) return '';
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
}

function timeAgo(ts) {
  if (!ts) return '-';
  const seconds = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
  return Math.floor(seconds / 86400) + 'd ago';
}

// --- System ---
async function loadSystem() {
  loadServiceLogs();
  await refreshCategories();
  renderCategories();
  try {
    const vmData = await api('GET', '/api/settings/vm-settings');
    document.getElementById('vm-keyboard').value = vmData.keyboard || '';
    document.getElementById('vm-timezone').value = vmData.timezone || '';
    document.getElementById('vm-ssh-keys').value = (vmData.ssh_authorized_keys || []).join('\n');
  } catch (e) {
    console.error('VM settings load error:', e);
  }
  try {
    const data = await api('GET', '/api/settings/ssh');
    const statusEl = document.getElementById('ssh-status');
    const btn = document.getElementById('ssh-toggle-btn');
    statusEl.textContent = data.enabled ? 'enabled' : 'disabled';
    statusEl.className = 'badge-status ' + (data.enabled ? 'approved' : 'denied');
    btn.textContent = data.enabled ? 'Disable' : 'Enable';
    btn.disabled = false;
  } catch (e) {
    console.error('System load error:', e);
  }
  try {
    const data = await api('GET', '/api/settings/learning-mode');
    const statusEl = document.getElementById('learning-mode-status');
    const btn = document.getElementById('learning-mode-toggle-btn');
    statusEl.textContent = data.enabled ? 'enabled' : 'disabled';
    statusEl.className = 'badge-status ' + (data.enabled ? 'approved' : 'denied');
    btn.textContent = data.enabled ? 'Disable' : 'Enable';
    btn.disabled = false;
  } catch (e) {
    console.error('Learning mode load error:', e);
  }
  loadLanguageSettings();
  loadDistroSettings();
}

async function loadServiceLogs() {
  const service = document.getElementById('service-log-select').value;
  const output = document.getElementById('service-log-output');
  output.textContent = 'Loading...';
  try {
    const data = await api('GET', '/api/system/logs?service=' + encodeURIComponent(service) + '&lines=200');
    output.textContent = data.logs || 'No log entries.';
    output.scrollTop = output.scrollHeight;
  } catch (e) {
    output.textContent = 'Error loading logs: ' + e.message;
  }
}

// Known language types and their display names
const LANGUAGE_TYPES = [
  { type: 'golang', name: 'Go Modules' },
  { type: 'npm', name: 'npm (Node.js)' },
  { type: 'pypi', name: 'PyPI (Python)' },
  { type: 'nuget', name: 'NuGet (.NET)' },
  { type: 'rust', name: 'Rust Crates' },
  { type: 'powershell', name: 'PowerShell Gallery' }
];

const DISTRO_TYPES = [
  { type: 'debian', name: 'Debian' },
  { type: 'ubuntu', name: 'Ubuntu' },
  { type: 'alpine', name: 'Alpine' }
];

async function loadLanguageSettings() {
  try {
    const data = await api('GET', '/api/settings/languages');
    const disabled = data.disabled || [];
    const container = document.getElementById('languages-list');
    if (!container) return;
    container.innerHTML = LANGUAGE_TYPES.map(lang => {
      const enabled = !disabled.includes(lang.type);
      return `<div class="setting-row" style="padding:4px 0">
        <div class="setting-info"><div class="setting-label">${lang.name}</div></div>
        <div class="setting-control">
          <span class="badge-status ${enabled ? 'approved' : 'denied'}">${enabled ? 'enabled' : 'disabled'}</span>
          <button class="btn btn-outline btn-sm" onclick="toggleLanguage('${lang.type}',${enabled})">${enabled ? 'Disable' : 'Enable'}</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    console.error('Language settings load error:', e);
  }
}

async function toggleLanguage(langType, currentlyEnabled) {
  const action = currentlyEnabled ? 'Disable' : 'Enable';
  if (!confirm(`${action} ${langType} packages?`)) return;
  try {
    const data = await api('GET', '/api/settings/languages');
    let disabled = data.disabled || [];
    if (currentlyEnabled) {
      disabled.push(langType);
    } else {
      disabled = disabled.filter(d => d !== langType);
    }
    await api('POST', '/api/settings/languages', { disabled });
    loadLanguageSettings();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function loadDistroSettings() {
  try {
    const data = await api('GET', '/api/settings/distros');
    const disabled = data.disabled || [];
    const container = document.getElementById('distros-list');
    if (!container) return;
    container.innerHTML = DISTRO_TYPES.map(distro => {
      const enabled = !disabled.includes(distro.type);
      return `<div class="setting-row" style="padding:4px 0">
        <div class="setting-info"><div class="setting-label">${distro.name}</div></div>
        <div class="setting-control">
          <span class="badge-status ${enabled ? 'approved' : 'denied'}">${enabled ? 'enabled' : 'disabled'}</span>
          <button class="btn btn-outline btn-sm" onclick="toggleDistro('${distro.type}',${enabled})">${enabled ? 'Disable' : 'Enable'}</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    console.error('Distro settings load error:', e);
  }
}

async function toggleDistro(distroType, currentlyEnabled) {
  const action = currentlyEnabled ? 'Disable' : 'Enable';
  if (!confirm(`${action} ${distroType} packages?`)) return;
  try {
    const data = await api('GET', '/api/settings/distros');
    let disabled = data.disabled || [];
    if (currentlyEnabled) {
      disabled.push(distroType);
    } else {
      disabled = disabled.filter(d => d !== distroType);
    }
    await api('POST', '/api/settings/distros', { disabled });
    loadDistroSettings();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function toggleLearningMode() {
  const statusEl = document.getElementById('learning-mode-status');
  const isEnabled = statusEl.textContent === 'enabled';
  if (!confirm(isEnabled ? 'Disable Learning Mode? New connections will require approval.' : 'Enable Learning Mode? All connections will be allowed by default.')) return;
  try {
    await api('POST', '/api/settings/learning-mode', { enabled: !isEnabled });
    loadSystem();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function toggleSSH() {
  const statusEl = document.getElementById('ssh-status');
  const isEnabled = statusEl.textContent === 'enabled';
  if (!confirm(isEnabled ? 'Disable SSH access?' : 'Enable SSH access?')) return;
  try {
    await api('POST', '/api/settings/ssh', { enabled: !isEnabled });
    loadSystem();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function saveVMSettings() {
  const keyboard = document.getElementById('vm-keyboard').value.trim();
  const timezone = document.getElementById('vm-timezone').value.trim();
  const sshKeysStr = document.getElementById('vm-ssh-keys').value.trim();
  const ssh_authorized_keys = sshKeysStr ? sshKeysStr.split('\n').map(k => k.trim()).filter(k => k) : [];
  try {
    await api('POST', '/api/settings/vm-settings', { keyboard, timezone, ssh_authorized_keys });
    alert('VM settings saved. SSH keys apply to new deployments. Keyboard and timezone apply to new image builds.');
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function doUpgrade() {
  const image = document.getElementById('upgrade-image').value.trim();
  if (!confirm('Upgrade to ' + image + '? The system will reboot after upgrade.')) return;
  try {
    await api('POST', '/api/system/upgrade', { image });
    alert('Upgrade started. The system will reboot when complete.');
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function doReboot() {
  if (!confirm('Reboot the appliance now?')) return;
  try {
    await api('POST', '/api/system/reboot', {});
    alert('Rebooting...');
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function renderCategories() {
  const container = document.getElementById('categories-list');
  if (!container) return;
  if (currentCategories.length === 0) {
    container.innerHTML = '<div style="color:var(--text-dim);font-size:13px;padding:8px 0">No categories defined yet.</div>';
    return;
  }
  container.innerHTML = currentCategories.map(c =>
    `<span class="category-badge" style="margin:2px 4px;padding:4px 10px;font-size:12px">${esc(c)} <span style="cursor:pointer;margin-left:6px;opacity:0.6" onclick="removeCategory('${esc(c)}')">&times;</span></span>`
  ).join('');
}

async function addCategory() {
  const input = document.getElementById('new-category-name');
  const name = input.value.trim();
  if (!name) { alert('Category name is required'); return; }
  try {
    await api('POST', '/api/categories', { name });
    input.value = '';
    await refreshCategories();
    renderCategories();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function removeCategory(name) {
  if (!confirm(`Delete category "${name}"?`)) return;
  try {
    await api('DELETE', '/api/categories?name=' + encodeURIComponent(name));
    await refreshCategories();
    renderCategories();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Disk Images & Agents ---

const osVersionDefaults = { alpine: '3.23', debian: '13', ubuntu: '24.04' };
const osLabels = { alpine: 'Alpine Linux', debian: 'Debian', ubuntu: 'Ubuntu' };

let currentDiskImages = [];
let editingDiskImageID = null;

async function loadAgents() {
  await loadSkills();
  await loadDiskImages();
  await loadAgentVMs();
}

async function loadDiskImages() {
  try {
    currentDiskImages = await api('GET', '/api/disk-images');
    const tbody = document.getElementById('disk-images-tbody');
    tbody.innerHTML = '';
    if (!currentDiskImages || currentDiskImages.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No disk images configured. Create one to get started.</td></tr>';
      return;
    }

    const aiToolLabels = {
      'opencode': 'OpenCode',
      'github_copilot': 'GitHub Copilot',
      'claude_code': 'Claude Code',
      'openai_codex': 'OpenAI Codex'
    };
    const containerToolLabels = {
      'docker': 'Docker',
      'nomad': 'Nomad',
      'kubernetes': 'Kubernetes'
    };

    currentDiskImages.forEach(img => {
      const osLabel = (osLabels[img.os] || img.os) + ' ' + (img.os_version || '');
      const pkgs = (img.packages && img.packages.length > 0) ? esc(img.packages.join(', ')) : '<span class="muted">none</span>';
      const aiTools = (img.ai_tools && img.ai_tools.length > 0)
        ? img.ai_tools.map(t => esc(aiToolLabels[t] || t)).join(', ')
        : '<span class="muted">none</span>';
      const ctTools = (img.container_tools && img.container_tools.length > 0)
        ? img.container_tools.map(t => esc(containerToolLabels[t] || t)).join(', ')
        : '<span class="muted">none</span>';

      // Build versions display.
      let versionsHTML = '';
      if (img.versions && img.versions.length > 0) {
        versionsHTML = img.versions.map(v => {
          const cls = imageVersionStatusClass(v.status);
          const sizeStr = v.size ? ' (' + formatBytes(v.size) + ')' : '';
          const label = 'v' + v.version + ': ' + v.status + (v.status_msg ? ' - ' + v.status_msg : '') + sizeStr;
          return `<span class="badge-status ${cls}">${esc(label)}</span>`;
        }).join(' ');
      } else {
        versionsHTML = '<span class="muted">no builds</span>';
      }

      tbody.innerHTML += `<tr>
        <td><strong>${esc(img.name)}</strong></td>
        <td>${esc(osLabel)}</td>
        <td>${pkgs}</td>
        <td>${aiTools}</td>
        <td>${ctTools}</td>
        <td>${versionsHTML}</td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="buildDiskImage('${esc(img.id)}')">Build</button>
          <button class="btn btn-outline btn-sm" onclick="editDiskImage('${esc(img.id)}')">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteDiskImage('${esc(img.id)}','${esc(img.name)}')">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Disk images load error:', e);
  }
}

function imageVersionStatusClass(status) {
  switch (status) {
    case 'ready': return 'approved';
    case 'building': return 'pending';
    case 'pending': return 'pending';
    case 'error': return 'denied';
    default: return '';
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function showCreateDiskImage() {
  editingDiskImageID = null;
  document.getElementById('modal-disk-image-title').textContent = 'Add Disk Image';
  document.getElementById('modal-disk-image-submit').textContent = 'Add';
  document.getElementById('disk-image-name').value = '';
  document.getElementById('disk-image-os').value = 'alpine';
  document.getElementById('disk-image-os-version').value = '';
  document.getElementById('disk-image-os-version').placeholder = osVersionDefaults['alpine'];
  document.getElementById('disk-image-packages').value = '';
  document.getElementById('disk-image-ai-opencode').checked = false;
  document.getElementById('disk-image-ai-github-copilot').checked = false;
  document.getElementById('disk-image-ai-claude-code').checked = false;
  document.getElementById('disk-image-ai-openai-codex').checked = false;
  document.getElementById('disk-image-ct-none').checked = true;
  document.getElementById('disk-image-scripts').value = '';
  document.getElementById('modal-disk-image').classList.add('active');
}

function hideDiskImageModal() {
  document.getElementById('modal-disk-image').classList.remove('active');
}

function updateDiskImageDefaults() {
  const os = document.getElementById('disk-image-os').value;
  document.getElementById('disk-image-os-version').placeholder = osVersionDefaults[os] || '';
}

function editDiskImage(id) {
  const img = currentDiskImages.find(x => x.id === id);
  if (!img) return;
  editingDiskImageID = id;
  document.getElementById('modal-disk-image-title').textContent = 'Edit Disk Image';
  document.getElementById('modal-disk-image-submit').textContent = 'Save';
  document.getElementById('disk-image-name').value = img.name || '';
  document.getElementById('disk-image-os').value = img.os || 'alpine';
  document.getElementById('disk-image-os-version').value = img.os_version || '';
  document.getElementById('disk-image-packages').value = (img.packages || []).join(', ');
  const aiTools = img.ai_tools || [];
  document.getElementById('disk-image-ai-opencode').checked = aiTools.includes('opencode');
  document.getElementById('disk-image-ai-github-copilot').checked = aiTools.includes('github_copilot');
  document.getElementById('disk-image-ai-claude-code').checked = aiTools.includes('claude_code');
  document.getElementById('disk-image-ai-openai-codex').checked = aiTools.includes('openai_codex');
  const ctTools = img.container_tools || [];
  if (ctTools.includes('nomad')) document.getElementById('disk-image-ct-nomad').checked = true;
  else if (ctTools.includes('kubernetes')) document.getElementById('disk-image-ct-kubernetes').checked = true;
  else if (ctTools.includes('docker')) document.getElementById('disk-image-ct-docker').checked = true;
  else document.getElementById('disk-image-ct-none').checked = true;
  document.getElementById('disk-image-scripts').value = (img.scripts || []).join('\n');
  document.getElementById('modal-disk-image').classList.add('active');
}

async function submitDiskImage() {
  const name = document.getElementById('disk-image-name').value.trim();
  const os = document.getElementById('disk-image-os').value;
  const osVersion = document.getElementById('disk-image-os-version').value.trim() || osVersionDefaults[os] || '';
  const packagesStr = document.getElementById('disk-image-packages').value.trim();
  const packages = packagesStr ? packagesStr.split(',').map(p => p.trim()).filter(p => p) : [];
  const ai_tools = [];
  if (document.getElementById('disk-image-ai-opencode').checked) ai_tools.push('opencode');
  if (document.getElementById('disk-image-ai-github-copilot').checked) ai_tools.push('github_copilot');
  if (document.getElementById('disk-image-ai-claude-code').checked) ai_tools.push('claude_code');
  if (document.getElementById('disk-image-ai-openai-codex').checked) ai_tools.push('openai_codex');
  const container_tools = [];
  const ctValue = document.querySelector('input[name="disk-image-container-tools"]:checked')?.value || 'none';
  if (ctValue === 'docker') container_tools.push('docker');
  else if (ctValue === 'nomad') { container_tools.push('docker'); container_tools.push('nomad'); }
  else if (ctValue === 'kubernetes') container_tools.push('kubernetes');
  const scriptsStr = document.getElementById('disk-image-scripts').value.trim();
  const scripts = scriptsStr ? scriptsStr.split('\n').filter(s => s.trim()) : [];

  if (!name) {
    alert('Name is required');
    return;
  }

  try {
    if (editingDiskImageID) {
      await api('PUT', '/api/disk-images', {
        id: editingDiskImageID, name, os, os_version: osVersion, packages, ai_tools, container_tools, scripts
      });
    } else {
      await api('POST', '/api/disk-images', {
        name, os, os_version: osVersion, packages, ai_tools, container_tools, scripts
      });
    }
    hideDiskImageModal();
    loadDiskImages();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteDiskImage(id, name) {
  if (!confirm(`Delete disk image "${name}" and all its built versions?`)) return;
  try {
    await api('DELETE', '/api/disk-images?id=' + encodeURIComponent(id));
    loadDiskImages();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function buildDiskImage(id) {
  try {
    const result = await api('POST', '/api/disk-images/build', { id });
    alert('Build started for version ' + result.version + '. This may take several minutes.');
    loadDiskImages();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

// --- Agent VMs ---

async function loadAgentVMs() {
  try {
    currentAgents = await api('GET', '/api/agents');
    const tbody = document.getElementById('agents-tbody');
    tbody.innerHTML = '';
    if (!currentAgents || currentAgents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No agents configured. Add one to get started.</td></tr>';
      return;
    }
    currentAgents.forEach(a => {
      const statusClass = agentStatusClass(a.status);
      const statusLabel = a.status_msg ? a.status + ': ' + a.status_msg : a.status;

      // Find the referenced disk image name.
      const img = currentDiskImages.find(x => x.id === a.image_id);
      const imgLabel = img ? esc(img.name) + (a.image_version ? ' v' + a.image_version : ' (latest)') : '<span class="muted">none</span>';

      // Show allocated skills.
      let skillsHTML = '<span class="muted">none</span>';
      if (a.skill_ids && a.skill_ids.length > 0) {
        skillsHTML = a.skill_ids.map(sid => {
          const sk = (currentSkills || []).find(s => s.id === sid);
          return `<span class="badge-status approved">${esc(sk ? sk.name : sid)}</span>`;
        }).join(' ');
      }

      // Build hostname display: link to VS Code Remote SSH when IP is available.
      let hostnameDisplay;
      const sshTarget = a.ip || a.hostname;
      if (sshTarget) {
        const vscodeURI = 'vscode://vscode-remote/ssh-remote+root@' + encodeURIComponent(sshTarget) + '/root';
        hostnameDisplay = `<a href="${vscodeURI}" title="Open in VS Code via Remote SSH"><strong>${esc(a.hostname)}</strong></a>`;
      } else {
        hostnameDisplay = `<strong>${esc(a.hostname)}</strong>`;
      }

      tbody.innerHTML += `<tr>
        <td>${hostnameDisplay}</td>
        <td><code>${esc(a.mac)}</code></td>
        <td>${a.ip ? '<code>' + esc(a.ip) + '</code>' : '<span class="muted">pending</span>'}</td>
        <td>${imgLabel}</td>
        <td>${skillsHTML}</td>
        <td><span class="badge-status ${statusClass}">${esc(statusLabel)}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="editAgent('${esc(a.id)}')">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteAgent('${esc(a.id)}','${esc(a.hostname)}')">Delete</button>
        </td>
      </tr>`;
    });
  } catch (e) {
    console.error('Agents load error:', e);
  }
}

function agentStatusClass(status) {
  switch (status) {
    case 'installed': return 'approved';
    case 'ready': return 'approved';
    case 'deploying': return 'pending';
    case 'error': return 'denied';
    default: return '';
  }
}

function populateAgentImageSelect(selectedID) {
  const sel = document.getElementById('agent-image-id');
  sel.innerHTML = '<option value="">-- Select a disk image --</option>';
  (currentDiskImages || []).forEach(img => {
    const osLabel = (osLabels[img.os] || img.os) + ' ' + (img.os_version || '');
    const opt = document.createElement('option');
    opt.value = img.id;
    opt.textContent = img.name + ' (' + osLabel + ')';
    if (img.id === selectedID) opt.selected = true;
    sel.appendChild(opt);
  });
}

function populateAgentSkillsList(selectedIDs) {
  const container = document.getElementById('agent-skills-list');
  container.innerHTML = '';
  const skills = currentSkills || [];
  if (skills.length === 0) {
    container.innerHTML = '<span class="muted">No skills available. Create skills in the Skills Library first.</span>';
    return;
  }
  const selected = new Set(selectedIDs || []);
  skills.forEach(s => {
    const label = document.createElement('label');
    label.style.display = 'block';
    label.style.padding = '4px 0';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = s.id;
    cb.checked = selected.has(s.id);
    cb.style.marginRight = '8px';
    label.appendChild(cb);
    label.appendChild(document.createTextNode(s.name + (s.active ? '' : ' (inactive)')));
    container.appendChild(label);
  });
}

function getSelectedAgentSkillIDs() {
  const container = document.getElementById('agent-skills-list');
  const checkboxes = container.querySelectorAll('input[type="checkbox"]:checked');
  return Array.from(checkboxes).map(cb => cb.value);
}

function showCreateAgent() {
  editingAgentID = null;
  document.getElementById('modal-agent-title').textContent = 'Add Agent';
  document.getElementById('modal-agent-submit').textContent = 'Add';
  document.getElementById('agent-mac').value = '';
  document.getElementById('agent-hostname').value = '';
  document.getElementById('agent-image-version').value = '0';
  document.getElementById('agent-disk').value = '/dev/sda';
  populateAgentImageSelect('');
  populateAgentSkillsList([]);
  document.getElementById('modal-agent').classList.add('active');
}

function hideAgentModal() {
  document.getElementById('modal-agent').classList.remove('active');
}

function editAgent(id) {
  const a = currentAgents.find(x => x.id === id);
  if (!a) return;
  editingAgentID = id;
  document.getElementById('modal-agent-title').textContent = 'Edit Agent';
  document.getElementById('modal-agent-submit').textContent = 'Save';
  document.getElementById('agent-mac').value = a.mac || '';
  document.getElementById('agent-hostname').value = a.hostname || '';
  document.getElementById('agent-image-version').value = a.image_version || 0;
  document.getElementById('agent-disk').value = a.disk_device || '/dev/sda';
  populateAgentImageSelect(a.image_id || '');
  populateAgentSkillsList(a.skill_ids || []);
  document.getElementById('modal-agent').classList.add('active');
}

async function submitAgent() {
  const mac = document.getElementById('agent-mac').value.trim();
  const hostname = document.getElementById('agent-hostname').value.trim();
  const image_id = document.getElementById('agent-image-id').value;
  const image_version = parseInt(document.getElementById('agent-image-version').value) || 0;
  const disk = document.getElementById('agent-disk').value.trim() || '/dev/sda';
  const skill_ids = getSelectedAgentSkillIDs();

  if (!mac || !hostname) {
    alert('MAC address and hostname are required');
    return;
  }
  if (!image_id) {
    alert('Please select a disk image');
    return;
  }

  try {
    if (editingAgentID) {
      await api('PUT', '/api/agents', {
        id: editingAgentID, mac, hostname, image_id, image_version, disk_device: disk, skill_ids
      });
    } else {
      await api('POST', '/api/agents', {
        mac, hostname, image_id, image_version, disk_device: disk, skill_ids
      });
    }
    hideAgentModal();
    loadAgentVMs();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteAgent(id, name) {
  if (!confirm(`Delete agent "${name}"?`)) return;
  try {
    await api('DELETE', '/api/agents?id=' + encodeURIComponent(id));
    loadAgentVMs();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function loadVersion() {
  try {
    const data = await api('GET', '/api/version');
    document.getElementById('version-display').textContent = (data.version || 'unknown');
  } catch (e) {
    // ignore
  }
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.sidebar nav a').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      navigate(a.dataset.page);
    });
  });
  const startPage = location.hash ? location.hash.substring(1) : 'dashboard';
  navigate(startPage);
  startPolling();
  loadVersion();
});
