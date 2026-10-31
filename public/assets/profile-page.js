'use strict';

const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const message = document.getElementById('profileMessage');
const list = document.getElementById('packageList');
const search = document.getElementById('packageSearch');
const filter = document.getElementById('packageFilter');
const refreshButton = document.getElementById('refreshPackages');
let packages = [];
let loading = false;

function setMessage(text, success = false) {
  message.textContent = text;
  message.classList.toggle('success', success);
}
function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes)) || Number(bytes) < 0) return 'Unknown size';
  const value = Number(bytes);
  if (value < 1024) return value + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = value / 1024, index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
  return size.toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' ' + units[index];
}
function formatDate(timestamp) {
  if (!Number.isFinite(Number(timestamp)) || Number(timestamp) <= 0) return 'Unknown';
  return new Date(Number(timestamp) * 1000).toLocaleString();
}
function isExpired(item) {
  return item.expires_at !== null && item.expires_at !== undefined && Number(item.expires_at) * 1000 <= Date.now();
}
function statusFor(item) {
  if (item.format === 'UNSUPPORTED_LEGACY') return { key: 'legacy', label: 'Unsupported legacy format' };
  if (item.format === 'MISSING') return { key: 'missing', label: 'Package file missing' };
  if (item.storage_available === false) return { key: 'missing', label: 'Package file missing' };
  if (item.revoked) return { key: 'revoked', label: 'Revoked' };
  if (isExpired(item)) return { key: 'expired', label: 'Expired' };
  return { key: 'active', label: 'Active' };
}
async function api(action, body = {}) {
  const response = await fetch('api.php?action=' + encodeURIComponent(action), {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfMeta?.content || '' },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    if (response.status === 401 || response.status === 403) window.location.replace('login.php');
    throw new Error(data.error || 'The request could not be completed.');
  }
  return data;
}
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function button(label, className, handler, disabled = false) {
  const node = element('button', className, label);
  node.type = 'button'; node.disabled = disabled;
  node.addEventListener('click', handler);
  return node;
}
function renderStats() {
  const totalBytes = packages.reduce((sum, item) => sum + Math.max(0, Number(item.size_bytes) || 0), 0);
  document.getElementById('statPackages').textContent = String(packages.length);
  document.getElementById('statStorage').textContent = formatBytes(totalBytes);
  document.getElementById('statActive').textContent = String(packages.filter(item => statusFor(item).key === 'active').length);
  document.getElementById('statRevoked').textContent = String(packages.filter(item => item.revoked).length);
}
function renderPackages() {
  list.replaceChildren();
  const needle = search.value.trim().toLowerCase();
  const selected = filter.value;
  const visible = packages.filter(item => {
    const status = statusFor(item);
    return (!needle || String(item.package_id).toLowerCase().includes(needle)) &&
      (selected === 'all' || selected === status.key);
  });
  if (!visible.length) {
    list.append(element('div', 'profile-empty', packages.length ? 'No packages match these filters.' : 'No encrypted packages are stored in this account yet.'));
    return;
  }
  for (const item of visible) {
    const status = statusFor(item);
    const card = element('article', 'profile-package');
    const head = element('div', 'profile-package-head');
    const identity = element('div', 'profile-package-identity');
    identity.append(element('span', 'profile-package-kicker', 'ENCRYPTED PACKAGE · SPKG'));
    identity.append(element('h3', '', 'Package ' + String(item.package_id).slice(0, 12)));
    identity.append(element('code', 'profile-package-id', item.package_id));
    const badge = element('span', 'profile-package-status status-' + status.key, status.label);
    head.append(identity, badge);
    const details = element('dl', 'profile-package-details');
    const fields = [
      ['Package size', item.storage_available === false ? 'Package unavailable' : formatBytes(item.size_bytes)],
      ['Stored on', formatDate(item.created_at)],
      ['Expiration', item.expires_at ? formatDate(item.expires_at) : 'No expiration set'],
      ['Storage', item.format === 'UNSUPPORTED_LEGACY' ? 'Unsupported legacy file' : item.storage_available === false ? 'Catalog record only' : 'Encrypted SPKG present'],
    ];
    for (const [label, value] of fields) {
      const wrapper = element('div');
      wrapper.append(element('dt', '', label), element('dd', '', value));
      details.append(wrapper);
    }
    const actions = element('div', 'profile-package-actions');
    const canDownload = item.format === 'SPKG' && !item.revoked && !isExpired(item) && item.storage_available !== false;
    actions.append(button('Download encrypted package', 'primary-button', async () => {
      try {
        setMessage('');
        const result = await api('access-token', { package_id: item.package_id });
        if (typeof result.download !== 'string' || !result.download.startsWith('download.php?token=')) throw new Error('Invalid download response.');
        window.location.assign(result.download);
      } catch (error) { setMessage(error instanceof Error ? error.message : 'Download failed.'); }
    }, !canDownload));
    const expiry = element('select', 'text-input profile-expiry');
    expiry.setAttribute('aria-label', 'Expiration for package ' + String(item.package_id).slice(0, 12));
    expiry.disabled = item.format !== 'SPKG';
    for (const [value, label] of [['', 'Change expiration…'], ['0', 'No expiration'], ['86400', 'Expire in 1 day'], ['604800', 'Expire in 7 days'], ['2592000', 'Expire in 30 days'], ['7776000', 'Expire in 90 days']]) {
      const option = element('option', '', label); option.value = value; expiry.append(option);
    }
    expiry.value = '';
    expiry.addEventListener('change', async () => {
      if (expiry.value === '') return;
      expiry.disabled = true;
      try {
        await api('set-expiry', { package_id: item.package_id, expires_in: Number(expiry.value) });
        setMessage('Package expiration updated.', true);
        await loadPackages(false);
      } catch (error) { setMessage(error instanceof Error ? error.message : 'Unable to update expiration.'); expiry.disabled = false; }
    });
    actions.append(expiry);
    actions.append(button('Revoke access', 'ghost-button', async () => {
      if (!window.confirm('Revoke download access for this package? This cannot be undone.')) return;
      try { await api('revoke', { package_id: item.package_id }); setMessage('Package access revoked.', true); await loadPackages(false); }
      catch (error) { setMessage(error instanceof Error ? error.message : 'Unable to revoke package.'); }
    }, item.format !== 'SPKG' || item.revoked || item.storage_available === false));
    actions.append(button('Delete permanently', 'danger-button', async () => {
      if (!window.confirm('Permanently delete this encrypted package from server storage? This cannot be undone.')) return;
      try { await api('delete', { package_id: item.package_id }); setMessage('Encrypted package deleted from server storage.', true); await loadPackages(false); }
      catch (error) { setMessage(error instanceof Error ? error.message : 'Unable to delete package.'); }
    }, item.storage_available === false));
    card.append(head, details, actions);
    list.append(card);
  }
}
async function loadPackages(showLoading = true) {
  if (loading) return;
  loading = true; refreshButton.disabled = true;
  if (showLoading) list.replaceChildren(element('div', 'profile-empty', 'Loading your encrypted package inventory…'));
  try {
    const data = await api('packages');
    packages = Array.isArray(data.packages) ? data.packages : [];
    renderStats(); renderPackages();
    setMessage(packages.length ? 'Inventory updated. Only packages belonging to your account are shown.' : 'No encrypted packages found for this account.', true);
  } catch (error) {
    list.replaceChildren(element('div', 'profile-empty', 'Could not load your package inventory.'));
    setMessage(error instanceof Error ? error.message : 'Could not load your package inventory.');
  } finally {
    loading = false; refreshButton.disabled = false;
  }
}
search.addEventListener('input', renderPackages);
filter.addEventListener('change', renderPackages);
refreshButton.addEventListener('click', () => loadPackages());
document.getElementById('logoutButton')?.addEventListener('click', async (event) => {
  const buttonNode = event.currentTarget;
  buttonNode.disabled = true;
  try {
    await api('logout');
    window.location.replace('login.php');
  } catch (error) {
    setMessage(error instanceof Error ? error.message : 'Unable to sign out.');
    buttonNode.disabled = false;
  }
});
loadPackages();
