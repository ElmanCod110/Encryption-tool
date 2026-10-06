const state = {
  csrf: document.querySelector('meta[name="csrf-token"]')?.content || '',
  jobId: null,
  pendingId: null,
  authMode: 'login',
  authenticated: false,
};

const $ = (id) => document.getElementById(id);

function log(value) {
  $('log').textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function setStatus(value) {
  $('statusPill').textContent = value;
  $('createState').textContent = value;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

async function api(action, options = {}) {
  const headers = { ...(options.headers || {}), 'X-CSRF-Token': state.csrf };
  const response = await fetch(`api.php?action=${encodeURIComponent(action)}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  });
  let payload = {};
  try { payload = await response.json(); } catch (_) {}
  if (!response.ok || payload.ok === false) throw new Error(payload.error || 'Request failed.');
  if (payload.csrf) state.csrf = payload.csrf;
  return payload;
}

function openAuth() { $('authModal').classList.remove('hidden'); }
function requireAuth() {
  if (state.authenticated) return true;
  openAuth();
  log('Sign in is required for package management.');
  return false;
}

function strength(input, output) {
  const value = $(input).value;
  const score = Math.min(100, Math.round((value.length / 32) * 100));
  $(output).style.width = `${score}%`;
}

function toggleSecret(inputId) {
  const input = $(inputId);
  input.type = input.type === 'password' ? 'text' : 'password';
}

function addLink(label, url) {
  $('log').textContent += `\n${label}: ${url}`;
}

$('showPassword').onclick = () => toggleSecret('password');
$('showPattern').onclick = () => toggleSecret('pattern');
$('password').oninput = () => strength('password', 'passwordStrength');
$('pattern').oninput = () => strength('pattern', 'patternStrength');

const zone = $('dropzone');
const fileInput = $('archive');
$('browseBtn').onclick = (event) => { event.stopPropagation(); fileInput.click(); };
zone.onclick = (event) => { if (!event.target.closest('button')) fileInput.click(); };
['dragenter', 'dragover'].forEach((name) => zone.addEventListener(name, (event) => { event.preventDefault(); zone.classList.add('drag'); }));
['dragleave', 'drop'].forEach((name) => zone.addEventListener(name, (event) => { event.preventDefault(); zone.classList.remove('drag'); }));
zone.addEventListener('drop', (event) => { const file = event.dataTransfer.files[0]; if (file) startUpload(file); });
fileInput.onchange = () => { if (fileInput.files[0]) startUpload(fileInput.files[0]); };

async function sha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function startUpload(file) {
  if (!/\.zip$/i.test(file.name)) { setStatus('ZIP required'); log('Please select a ZIP archive.'); return; }
  if (!requireAuth()) return;
  try {
    $('uploadProgress').classList.remove('hidden');
    $('uploadProgressBar').style.width = '0%';
    $('uploadProgressText').textContent = '0%';
    $('uploadProgressSize').textContent = `0 / ${formatBytes(file.size)}`;
    setStatus('Hashing upload');
    const checksum = file.size <= 512 * 1024 * 1024 ? await sha256(file) : null;
    const init = await api('upload-init', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ total_bytes: file.size, sha256: checksum }) });
    const upload = init.upload;
    const chunkSize = upload.chunk_size || 8 * 1024 * 1024;
    for (let offset = 0; offset < file.size; offset += chunkSize) {
      const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size));
      await api('upload-chunk', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Upload-ID': upload.id, 'X-Upload-Offset': String(offset) }, body: chunk });
      const received = Math.min(offset + chunk.size, file.size);
      const percent = Math.round(received / file.size * 100);
      $('uploadProgressBar').style.width = `${percent}%`;
      $('uploadProgressText').textContent = `${percent}%`;
      $('uploadProgressSize').textContent = `${formatBytes(received)} / ${formatBytes(file.size)}`;
    }
    const complete = await api('upload-complete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ upload_id: upload.id }) });
    state.jobId = complete.job_id;
    state.pendingId = complete.state.pending?.[0]?.id || null;
    $('createFlow').classList.remove('hidden');
    $('buildFooter').classList.remove('hidden');
    $('archiveNotice').textContent = state.pendingId ? 'A protected archive is waiting for a password.' : 'All archives are processed.';
    setStatus(complete.state.status);
    log(complete.state);
  } catch (error) {
    setStatus('Upload failed');
    log(error.message);
  }
}

$('stepBtn').onclick = async () => {
  try {
    if (!state.jobId || !state.pendingId) throw new Error('No protected archive is pending.');
    if ($('archivePassword').classList.contains('hidden')) {
      $('archivePassword').classList.remove('hidden');
      $('archivePassword').focus();
      $('stepBtn').textContent = 'Process protected archive';
      return;
    }
    const data = await api('archive-step', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ job_id: state.jobId, archive_id: state.pendingId, password: $('archivePassword').value }) });
    state.pendingId = data.state.pending?.[0]?.id || null;
    $('archivePassword').value = '';
    $('archivePassword').classList.toggle('hidden', !state.pendingId);
    $('stepBtn').textContent = state.pendingId ? 'Process protected archive' : 'Done';
    $('archiveNotice').textContent = state.pendingId ? 'Another protected archive is waiting for a password.' : 'All archives are processed.';
    setStatus(data.state.status);
    log(data.state);
  } catch (error) {
    setStatus('Archive step failed');
    log(error.message);
  }
};

$('buildBtn').onclick = async () => {
  try {
    if (!requireAuth()) return;
    if (!state.jobId) throw new Error('Upload a ZIP archive first.');
    const data = await api('build', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        job_id: state.jobId,
        project_name: $('projectName').value,
        password: $('password').value,
        pattern: $('pattern').value,
        create_recovery: $('createRecovery').checked,
      }),
    });
    const safeLog = { ...data };
    delete safeLog.recovery_key;
    log(safeLog);
    setStatus('V14 package created');
    $('packageId').value = data.package_id;
    addLink('Download encrypted package', data.download);
    if (data.recovery_key) {
      $('recoveryKey').textContent = data.recovery_key;
      $('recoveryCard').classList.remove('hidden');
    }
    await loadPackages();
    $('password').value = '';
    $('pattern').value = '';
  } catch (error) {
    setStatus('Build failed');
    log(error.message);
  }
};

$('copyRecovery').onclick = async () => {
  const value = $('recoveryKey').textContent;
  try {
    await navigator.clipboard.writeText(value);
    $('copyRecovery').textContent = 'Copied';
    setTimeout(() => { $('copyRecovery').textContent = 'Copy key'; }, 1400);
  } catch (_) {
    log('Copy was blocked by the browser; select the recovery key manually.');
  }
};

$('decryptBtn').onclick = async () => {
  try {
    const recoveryKey = $('recoveryKeyInput').value.trim();
    const data = await api('decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package_id: $('packageId').value.trim(),
        password: $('decryptPassword').value,
        pattern: $('decryptPattern').value,
        recovery_key: recoveryKey || null,
      }),
    });
    setStatus('Package restored');
    log(data);
    addLink('Download restored files', data.restore_download);
    $('decryptPassword').value = '';
    $('decryptPattern').value = '';
    $('recoveryKeyInput').value = '';
  } catch (error) {
    setStatus('Unable to open package');
    log(error.message);
  }
};

async function loadPackages() {
  if (!state.authenticated) return;
  try {
    const data = await api('packages', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    renderPackages(data.packages);
  } catch (error) { log(error.message); }
}

function renderPackages(items) {
  const box = $('packageList');
  if (!items.length) {
    box.className = 'package-list empty';
    box.innerHTML = '<div class="empty-icon"><svg viewBox="0 0 32 32"><path d="M5 9h8l2 3h12v13H5z"/><path d="M5 9V7h9l2 2"/></svg></div><strong>No managed packages</strong><span>Create a package or sign in to see managed items.</span>';
    return;
  }
  box.className = 'package-list';
  box.replaceChildren();
  items.slice(0, 12).forEach((item) => {
    const row = document.createElement('div'); row.className = 'pkg-row';
    const meta = document.createElement('div'); meta.className = 'pkg-meta';
    const strong = document.createElement('strong'); strong.textContent = item.package_id;
    const span = document.createElement('span'); span.textContent = item.revoked ? 'Revoked' : item.expires_at ? `Expires ${new Date(item.expires_at * 1000).toLocaleString()}` : `Created ${new Date(item.created_at * 1000).toLocaleString()}`;
    meta.append(strong, span);
    const actions = document.createElement('div'); actions.className = 'pkg-actions';

    const link = document.createElement('button'); link.textContent = 'Link';
    link.onclick = async () => { try { const data = await api('access-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package_id: item.package_id }) }); window.open(data.download, '_blank', 'noopener'); } catch (error) { log(error.message); } };

    const expiry = document.createElement('button'); expiry.textContent = 'Expiry';
    expiry.onclick = async () => {
      const days = prompt('Expiration in days. Use 0 for no expiration.', item.expires_at ? Math.max(1, Math.ceil((item.expires_at - Date.now() / 1000) / 86400)) : 0);
      if (days === null) return;
      try { await api('set-expiry', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package_id: item.package_id, expires_in: Number(days) * 86400 }) }); loadPackages(); } catch (error) { log(error.message); }
    };

    const revoke = document.createElement('button'); revoke.textContent = item.revoked ? 'Revoked' : 'Revoke'; revoke.disabled = item.revoked;
    revoke.onclick = async () => { if (!confirm('Revoke this package? Existing access links will stop working.')) return; try { await api('revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package_id: item.package_id }) }); loadPackages(); } catch (error) { log(error.message); } };

    const remove = document.createElement('button'); remove.textContent = 'Delete';
    remove.onclick = async () => { if (!confirm('Delete the package permanently? The reserved name remains unavailable.')) return; try { await api('delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package_id: item.package_id }) }); loadPackages(); } catch (error) { log(error.message); } };

    actions.append(link, expiry, revoke, remove); row.append(meta, actions); box.appendChild(row);
  });
}

$('refreshPackages').onclick = async () => { if (requireAuth()) loadPackages(); };
const modal = $('authModal');
$('authButton').onclick = openAuth;
$('closeAuth').onclick = () => modal.classList.add('hidden');
$('loginTab').onclick = () => switchAuth('login');
$('registerTab').onclick = () => switchAuth('register');

function switchAuth(mode) {
  state.authMode = mode;
  $('loginTab').classList.toggle('active', mode === 'login');
  $('registerTab').classList.toggle('active', mode === 'register');
  $('authTitle').textContent = mode === 'login' ? 'Sign in' : 'Create account';
  $('authSubmit').textContent = mode === 'login' ? 'Sign in' : 'Create account';
  $('authPassword').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
}

$('authSubmit').onclick = async () => {
  try {
    const action = state.authMode === 'login' ? 'login' : 'register';
    const data = await api(action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: $('authUsername').value, password: $('authPassword').value }) });
    state.authenticated = true;
    $('authPassword').value = '';
    modal.classList.add('hidden');
    $('authButton').textContent = 'Account';
    log(data);
    await loadPackages();
  } catch (error) { log(error.message); }
};

$('logoutButton').onclick = async () => {
  try {
    const data = await api('logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    state.authenticated = false;
    $('authButton').textContent = 'Sign in';
    $('packageList').className = 'package-list empty';
    $('packageList').innerHTML = '<strong>Signed out</strong><span>Sign in again to manage packages.</span>';
    log(data);
  } catch (error) { log(error.message); }
};

(async () => {
  try {
    const me = await api('me', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    state.authenticated = !!me.authenticated;
    if (state.authenticated) { $('authButton').textContent = 'Account'; loadPackages(); }
    const status = await api('security-status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    $('log').textContent = `Format: ${status.format}\nCrypto: ${status.crypto.kdf} + ${status.crypto.aead}\nControls: ${Object.entries(status.controls).filter(([, value]) => value).map(([name]) => name).join(', ')}`;

    const healthResponse = await fetch('health.php', { credentials: 'same-origin', cache: 'no-store' });
    const health = await healthResponse.json();
    if (!health.ok) {
      const missing = Object.entries(health.required || {}).filter(([, value]) => value === false).map(([name]) => name);
      setStatus('Server setup incomplete');
      log(`Server runtime is not ready. Missing/disabled required components: ${missing.join(', ') || 'see health.php'}`);
    }
  } catch (_) {}
})();
