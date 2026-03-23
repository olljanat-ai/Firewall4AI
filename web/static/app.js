// Firewall4AI Admin UI
const API = '';
let pollInterval = null;
let lastLogID = 0;

// Edit state trackers
let editingRule = null;       // null = adding, { host, pathPrefix, skillID, sourceIP } = editing
let editingImageRule = null;  // null = adding, { host, skillID, sourceIP } = editing
let editingSkillID = null;    // null = creating, string = editing
let editingCredID = null;     // null = creating, string = editing

// Cached data for edit lookups
let currentApprovals = [];
let currentImages = [];
let currentSkills = [];
let currentCredentials = [];
let currentCategories = [];
let currentLogs = [];

// --- Navigation ---
function navigate(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  if (page === 'dashboard') loadDashboard();
  if (page === 'approvals') loadApprovals();
  if (page === 'images') loadImages();
  if (page === 'skills') loadSkills();
  if (page === 'credentials') loadCredentials();
  if (page === 'logs') loadLogs();
  if (page === 'settings') loadSettings();
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
    const [stats, pending, pendingImages] = await Promise.all([
      api('GET', '/api/logs/stats'),
      api('GET', '/api/approvals/pending'),
      api('GET', '/api/images/pending'),
      refreshSkills(),
    ]);
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-allowed').textContent = stats.allowed || 0;
    document.getElementById('stat-denied').textContent = stats.denied || 0;
    document.getElementById('stat-pending').textContent = stats.pending || 0;
    document.getElementById('pending-count').textContent = (pending.length || 0) + (pendingImages.length || 0);
    // Update sidebar badges
    const badge = document.getElementById('approval-badge');
    if (pending.length > 0) {
      badge.textContent = pending.length;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
    const imageBadge = document.getElementById('image-badge');
    if (pendingImages.length > 0) {
      imageBadge.textContent = pendingImages.length;
      imageBadge.style.display = 'inline';
    } else {
      imageBadge.style.display = 'none';
    }
    // Recent pending (hosts + images combined)
    const tbody = document.getElementById('dash-pending-tbody');
    tbody.innerHTML = '';
    const allPending = [
      ...(pending || []).map(a => ({ ...a, _type: 'host' })),
      ...(pendingImages || []).map(a => ({ ...a, _type: 'image' })),
    ];
    if (allPending.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No pending approvals</td></tr>';
    } else {
      allPending.slice(0, 10).forEach(a => {
        const skillDisplay = formatSkillID(a.skill_id);
        const sourceDisplay = formatSourceIP(a.source_ip);
        const pathDisplay = a._type === 'host' ? formatPathPrefix(a.path_prefix) : '';
        const apiPath = a._type === 'image' ? '/api/images/decide' : '/api/approvals/decide';
        const typeLabel = a._type === 'image' ? '<span class="badge-status pending">image</span> ' : '';
        const pp = a.path_prefix || '';
        const approveBtn = `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','approved')">Approve</button>`;
        const vmBtn = a.source_ip ? `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','','${esc(a.source_ip)}','${esc(pp)}','approved')" title="Approve for this VM">Approve VM</button>` : '';
        const globalBtn = (a.skill_id || a.source_ip) ? `<button class="btn btn-success btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','','','${esc(pp)}','approved')" title="Approve for all agents">Approve Global</button>` : '';
        const denyBtn = `<button class="btn btn-danger btn-sm" onclick="decideDash('${apiPath}','${esc(a.host)}','${esc(a.skill_id)}','${esc(a.source_ip)}','${esc(pp)}','denied')">Deny</button>`;
        tbody.innerHTML += `<tr>
          <td>${typeLabel}<strong>${esc(a.host)}</strong></td>
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
  return true;
}

function clearFilters(prefix) {
  const cat = document.getElementById('filter-' + prefix + '-category');
  const skill = document.getElementById('filter-' + prefix + '-skill');
  const ip = document.getElementById('filter-' + prefix + '-ip');
  const status = document.getElementById('filter-' + prefix + '-status');
  if (cat) cat.value = '';
  if (skill) skill.value = '';
  if (ip) ip.value = '';
  if (status) status.value = '';
  if (prefix === 'url') loadApprovals();
  if (prefix === 'image') loadImages();
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
    const [approvals] = await Promise.all([
      api('GET', '/api/approvals'),
      refreshCategories(),
      refreshSkills(),
    ]);
    currentApprovals = approvals || [];
    populateFilterDropdowns('url', currentApprovals);
    const pending = currentApprovals.filter(a => a.status === 'pending');
    const badge = document.getElementById('approval-badge');
    if (pending.length > 0) {
      badge.textContent = pending.length;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
    const filter = getFilter('url');
    const filtered = currentApprovals.filter(a => matchesFilter(a, filter));
    const tbody = document.getElementById('approvals-tbody');
    tbody.innerHTML = '';
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No URL rules</td></tr>';
      return;
    }
    filtered.sort((a, b) => a.host.localeCompare(b.host));
    filtered.forEach((a) => {
      const idx = currentApprovals.indexOf(a);
      const skillDisplay = formatSkillID(a.skill_id);
      const sourceDisplay = formatSourceIP(a.source_ip);
      const pathDisplay = formatPathPrefix(a.path_prefix);
      const categoryDisplay = formatCategory(a.category);
      const pp = a.path_prefix || '';
      const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditRule(${idx})" title="Edit rule">Edit</button>`;
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
      tbody.innerHTML += `<tr>
        <td><strong>${esc(a.host)}</strong></td>
        <td>${pathDisplay}</td>
        <td>${categoryDisplay}</td>
        <td>${logModeDisplay}</td>
        <td>${skillDisplay}</td>
        <td>${sourceDisplay}</td>
        <td><span class="badge-status ${a.status}">${a.status}</span></td>
        <td>${timeAgo(a.updated_at)}</td>
        <td>${actions}</td>
      </tr>`;
    });
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
    const [images] = await Promise.all([
      api('GET', '/api/images'),
      refreshCategories(),
      refreshSkills(),
    ]);
    currentImages = images || [];
    populateFilterDropdowns('image', currentImages);
    const pending = currentImages.filter(a => a.status === 'pending');
    const badge = document.getElementById('image-badge');
    if (pending.length > 0) {
      badge.textContent = pending.length;
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
    const filter = getFilter('image');
    const filtered = currentImages.filter(a => matchesFilter(a, filter));
    const tbody = document.getElementById('images-tbody');
    tbody.innerHTML = '';
    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No image approval records</td></tr>';
      return;
    }
    filtered.sort((a, b) => a.host.localeCompare(b.host));
    filtered.forEach((a) => {
      const idx = currentImages.indexOf(a);
      const skillDisplay = formatSkillID(a.skill_id);
      const sourceDisplay = formatSourceIP(a.source_ip);
      const categoryDisplay = formatCategory(a.category);
      const editBtn = `<button class="btn btn-outline btn-sm" onclick="showEditImageRule(${idx})" title="Edit rule">Edit</button>`;
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
      tbody.innerHTML += `<tr>
        <td><strong>${esc(a.host)}</strong></td>
        <td>${categoryDisplay}</td>
        <td>${skillDisplay}</td>
        <td>${sourceDisplay}</td>
        <td><span class="badge-status ${a.status}">${a.status}</span></td>
        <td>${timeAgo(a.updated_at)}</td>
        <td>${actions}</td>
      </tr>`;
    });
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

// --- Skills ---
async function loadSkills() {
  try {
    const skills = await api('GET', '/api/skills');
    currentSkills = skills || [];
    currentSkills.sort((a, b) => a.name.localeCompare(b.name));
    const tbody = document.getElementById('skills-tbody');
    tbody.innerHTML = '';
    if (currentSkills.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No skills configured. Create one to get started.</td></tr>';
      return;
    }
    currentSkills.forEach((s, idx) => {
      tbody.innerHTML += `<tr>
        <td><strong>${esc(s.id)}</strong></td>
        <td>${esc(s.name)}</td>
        <td>${(s.allowed_hosts || []).map(h => `<span class="badge-status approved">${esc(h)}</span>`).join(' ') || '<span class="badge-status denied">none</span>'}</td>
        <td><span class="badge-status ${s.active ? 'approved' : 'denied'}">${s.active ? 'active' : 'inactive'}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="showEditSkill(${idx})">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deleteSkill('${esc(s.id)}')">Delete</button>
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
  document.getElementById('skill-id').value = '';
  document.getElementById('skill-id').readOnly = false;
  document.getElementById('skill-id-group').querySelector('label').textContent = 'Skill ID (optional, auto-generated if empty)';
  document.getElementById('skill-name').value = '';
  document.getElementById('skill-hosts').value = '';
  document.getElementById('skill-active-group').style.display = 'none';
  document.getElementById('modal-skill').classList.add('active');
}

function showEditSkill(idx) {
  const s = currentSkills[idx];
  if (!s) return;
  editingSkillID = s.id;
  document.getElementById('modal-skill-title').textContent = 'Edit Skill';
  document.getElementById('modal-skill-submit').textContent = 'Save';
  document.getElementById('skill-id').value = s.id;
  document.getElementById('skill-id').readOnly = true;
  document.getElementById('skill-id-group').querySelector('label').textContent = 'Skill ID (read-only)';
  document.getElementById('skill-name').value = s.name;
  document.getElementById('skill-hosts').value = (s.allowed_hosts || []).join('\n');
  document.getElementById('skill-active-group').style.display = 'block';
  document.getElementById('skill-active').value = s.active ? 'true' : 'false';
  document.getElementById('modal-skill').classList.add('active');
}

function hideSkillModal() {
  document.getElementById('modal-skill').classList.remove('active');
  editingSkillID = null;
}

async function submitSkill() {
  if (editingSkillID) {
    await updateSkill();
  } else {
    await createSkill();
  }
}

async function createSkill() {
  const id = document.getElementById('skill-id').value.trim();
  const name = document.getElementById('skill-name').value.trim();
  const hosts = document.getElementById('skill-hosts').value.trim().split(/[\n,]+/).map(h => h.trim()).filter(Boolean);
  if (!name) { alert('Name is required'); return; }
  try {
    const body = { name, allowed_hosts: hosts };
    if (id) body.id = id;
    const result = await api('POST', '/api/skills', body);
    hideSkillModal();
    loadSkills();
    alert('Skill created!\n\nID: ' + result.id + '\nToken: ' + result.token);
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function updateSkill() {
  const id = editingSkillID;
  const name = document.getElementById('skill-name').value.trim();
  const hosts = document.getElementById('skill-hosts').value.trim().split(/[\n,]+/).map(h => h.trim()).filter(Boolean);
  const active = document.getElementById('skill-active').value === 'true';
  if (!name) { alert('Name is required'); return; }
  try {
    await api('PUT', '/api/skills', { id, name, allowed_hosts: hosts, active, token: '' });
    hideSkillModal();
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function deleteSkill(id) {
  if (!confirm(`Delete skill "${id}"?`)) return;
  try {
    await api('DELETE', '/api/skills?id=' + encodeURIComponent(id));
    loadSkills();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

function copyToken(el) {
  navigator.clipboard.writeText(el.textContent);
  const orig = el.textContent;
  el.textContent = 'Copied!';
  setTimeout(() => { el.textContent = orig; }, 1000);
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
        <td>${formatSkillID(c.skill_id)}</td>
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
}

function showCreateCred() {
  editingCredID = null;
  document.getElementById('modal-cred-title').textContent = 'Add Credential';
  document.getElementById('modal-cred-submit').textContent = 'Add';
  document.getElementById('cred-name').value = '';
  document.getElementById('cred-host').value = '';
  document.getElementById('cred-skill').value = '';
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
  document.getElementById('cred-skill').value = c.skill_id || '';
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
    skill_id: document.getElementById('cred-skill').value.trim(),
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
    skill_id: document.getElementById('cred-skill').value.trim(),
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
      (async () => { try { currentApprovals = await api('GET', '/api/approvals') || []; } catch (e) {} })(),
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
function startPolling() {
  pollInterval = setInterval(async () => {
    try {
      const [pending, pendingImages] = await Promise.all([
        api('GET', '/api/approvals/pending'),
        api('GET', '/api/images/pending'),
      ]);
      const badge = document.getElementById('approval-badge');
      if (pending && pending.length > 0) {
        badge.textContent = pending.length;
        badge.style.display = 'inline';
      } else {
        badge.style.display = 'none';
      }
      const imageBadge = document.getElementById('image-badge');
      if (pendingImages && pendingImages.length > 0) {
        imageBadge.textContent = pendingImages.length;
        imageBadge.style.display = 'inline';
      } else {
        imageBadge.style.display = 'none';
      }
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
      // Refresh dashboard or images page if active
      if (document.getElementById('page-dashboard').classList.contains('active')) {
        loadDashboard();
      }
      if (document.getElementById('page-images').classList.contains('active')) {
        loadImages();
      }
    } catch (e) {
      // Silently ignore poll errors
    }
  }, 3000);
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

// --- Settings ---
async function loadSettings() {
  await refreshCategories();
  renderCategories();
  try {
    const data = await api('GET', '/api/settings/ssh');
    const statusEl = document.getElementById('ssh-status');
    const btn = document.getElementById('ssh-toggle-btn');
    statusEl.textContent = data.enabled ? 'enabled' : 'disabled';
    statusEl.className = 'badge-status ' + (data.enabled ? 'approved' : 'denied');
    btn.textContent = data.enabled ? 'Disable' : 'Enable';
    btn.disabled = false;
  } catch (e) {
    console.error('Settings load error:', e);
  }
}

async function toggleSSH() {
  const statusEl = document.getElementById('ssh-status');
  const isEnabled = statusEl.textContent === 'enabled';
  if (!confirm(isEnabled ? 'Disable SSH access?' : 'Enable SSH access?')) return;
  try {
    await api('POST', '/api/settings/ssh', { enabled: !isEnabled });
    loadSettings();
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
  navigate('dashboard');
  startPolling();
  loadVersion();
});
