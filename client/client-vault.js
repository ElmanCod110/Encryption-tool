const $ = (id) => document.getElementById(id);
const state = { worker: null, pending: new Map(), counter: 0 };

function log(message) { $('log').textContent = `${new Date().toLocaleTimeString()}  ${message}\n` + $('log').textContent; }
function bytesToBase64(bytes) { let s = ''; const a = new Uint8Array(bytes); for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000)); return btoa(s); }
function base64ToBytes(value) { const s = atob(value); const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
function randomBytes(n) { const out = new Uint8Array(n); crypto.getRandomValues(out); return out; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; }
function readU32(view, offset) { return view.getUint32(offset, false); }
function concat(...parts) { const size = parts.reduce((n, p) => n + p.length, 0); const out = new Uint8Array(size); let off = 0; for (const p of parts) { out.set(p, off); off += p.length; } return out; }
function encoder() { return new TextEncoder(); }
function decoder() { return new TextDecoder(); }
async function hashText(value) { const d = await crypto.subtle.digest('SHA-256', encoder().encode(value)); return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join(''); }

function workerCall(op, payload) {
  if (!state.worker) {
    state.worker = new Worker('workers/crypto-worker.js', { type: 'classic' });
    state.worker.onmessage = (e) => { const p = state.pending.get(e.data.id); if (!p) return; state.pending.delete(e.data.id); e.data.ok ? p.resolve(e.data.result) : p.reject(new Error(e.data.error)); };
  }
  return new Promise((resolve, reject) => { const id = ++state.counter; state.pending.set(id, { resolve, reject }); state.worker.postMessage({ id, op, ...payload }); });
}

async function startSession(password, pattern, salt) {
  return (await workerCall('start', { password, pattern, salt, iterations: 900000 })).sessionId;
}

function validateSecrets(password, pattern) {
  if (password.length < 12 || pattern.length < 12) throw new Error('Password and pattern must contain at least 12 characters.');
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^\p{L}\p{N}]/u.test(password)) throw new Error('Password must contain lowercase, uppercase, numeric, and special characters.');
  if (pattern.replaceAll(pattern[0], '').length < 4) throw new Error('Pattern is too repetitive.');
}

async function encryptFiles(files, password, pattern) {
  validateSecrets(password, pattern);
  const packageId = [...randomBytes(24)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const salt = randomBytes(32);
  const iterations = 900000;
  const sessionId = await startSession(password, pattern, salt);
  try {
    const manifest = { format: 'SECURE-BROWSER-V6', version: 6, package_id: packageId, nodes: [] };
    const records = [];
    for (const file of files) {
      const id = [...randomBytes(16)].map(b=>b.toString(16).padStart(2,'0')).join('');
      const blobId = [...randomBytes(20)].map(b=>b.toString(16).padStart(2,'0')).join('');
      const aad = `${packageId}|file|${id}`;
      const iv = randomBytes(12);
      const encrypted = await workerCall('encrypt', { sessionId, purpose: 'file', iv, plaintext: new Uint8Array(await file.arrayBuffer()), aad });
      const nameIv = randomBytes(12);
      const encName = await workerCall('encrypt', { sessionId, purpose: 'name', iv: nameIv, plaintext: encoder().encode(file.webkitRelativePath || file.name), aad: `${packageId}|name|${id}` });
      manifest.nodes.push({ id, type: 'file', name_iv: bytesToBase64(nameIv), name: bytesToBase64(encName), blob: blobId, size: file.size });
      records.push({ id: blobId, iv, ciphertext: new Uint8Array(encrypted) });
    }
    const manifestIv = randomBytes(12);
    const manifestCipher = await workerCall('encrypt', { sessionId, purpose: 'manifest', iv: manifestIv, plaintext: encoder().encode(JSON.stringify(manifest)), aad: `${packageId}|manifest|6` });
    const header = encoder().encode(JSON.stringify({ magic:'SPCB6', format:'SECURE-BROWSER-V6', version:6, package_id:packageId, salt:bytesToBase64(salt), iterations, manifest_iv:bytesToBase64(manifestIv) }));
    const chunks = [encoder().encode('SPCB6\n'), u32(header.length), header, u32(new Uint8Array(manifestCipher).length), new Uint8Array(manifestCipher)];
    for (const record of records) {
      const meta = encoder().encode(JSON.stringify({ id: record.id, iv: bytesToBase64(record.iv), size: record.ciphertext.length }));
      chunks.push(u32(meta.length), meta, u32(record.ciphertext.length), record.ciphertext);
    }
    return { blob: new Blob(chunks, { type:'application/octet-stream' }), packageId };
  } finally {
    await workerCall('destroy', { sessionId }).catch(() => {});
  }
}

async function parsePackage(file) {
  const data = new Uint8Array(await file.arrayBuffer());
  let offset = 0;
  const magic = decoder().decode(data.subarray(0, 6)); offset += 6;
  if (magic !== 'SPCB6\n') throw new Error('Unsupported browser package.');
  const hlen = readU32(new DataView(data.buffer), offset); offset += 4;
  const header = JSON.parse(decoder().decode(data.subarray(offset, offset+hlen))); offset += hlen;
  const mlen = readU32(new DataView(data.buffer), offset); offset += 4;
  const manifestCipher = data.slice(offset, offset+mlen); offset += mlen;
  const records = new Map();
  while (offset < data.length) {
    if (offset + 4 > data.length) throw new Error('Package is truncated.');
    const metaLen = readU32(new DataView(data.buffer), offset); offset += 4;
    if (offset + metaLen > data.length) throw new Error('Package metadata is truncated.');
    const meta = JSON.parse(decoder().decode(data.subarray(offset, offset+metaLen))); offset += metaLen;
    const cipherLen = readU32(new DataView(data.buffer), offset); offset += 4;
    if (offset + cipherLen > data.length) throw new Error('Package blob is truncated.');
    const cipher = data.slice(offset, offset+cipherLen); offset += cipherLen;
    records.set(meta.id, { iv: base64ToBytes(meta.iv), ciphertext: cipher });
  }
  return { header, manifestCipher, records };
}

async function decryptFiles(file, password, pattern) {
  const pkg = await parsePackage(file);
  const salt = base64ToBytes(pkg.header.salt);
  const sessionId = await startSession(password, pattern, salt);
  try {
    const manifestPlain = await workerCall('decrypt', { sessionId, purpose: 'manifest', iv: base64ToBytes(pkg.header.manifest_iv), ciphertext: pkg.manifestCipher, aad: `${pkg.header.package_id}|manifest|6` });
    const manifest = JSON.parse(decoder().decode(new Uint8Array(manifestPlain)));
    if (manifest.format !== 'SECURE-BROWSER-V6' || manifest.version !== 6 || manifest.package_id !== pkg.header.package_id || !Array.isArray(manifest.nodes)) throw new Error('Browser package manifest is invalid.');
    const output = [];
    const seenBlobs = new Set();
    for (const node of manifest.nodes) {
      if (node.type !== 'file' || typeof node.id !== 'string' || typeof node.blob !== 'string' || seenBlobs.has(node.blob)) throw new Error('Browser package manifest is invalid.');
      seenBlobs.add(node.blob);
      const record = pkg.records.get(node.blob);
      if (!record) throw new Error('Package blob inventory does not match the manifest.');
      const namePlain = await workerCall('decrypt', { sessionId, purpose: 'name', iv: base64ToBytes(node.name_iv), ciphertext: base64ToBytes(node.name), aad: `${pkg.header.package_id}|name|${node.id}` });
      const content = await workerCall('decrypt', { sessionId, purpose: 'file', iv: record.iv, ciphertext: record.ciphertext, aad: `${pkg.header.package_id}|file|${node.id}` });
      output.push({ name: decoder().decode(new Uint8Array(namePlain)), content: new Blob([content], { type:'application/octet-stream' }) });
    }
    if (seenBlobs.size !== pkg.records.size) throw new Error('Package blob inventory does not match the manifest.');
    return output;
  } finally {
    await workerCall('destroy', { sessionId }).catch(() => {});
  }
}

function downloadBlob(blob, filename) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 10000); }
function safeParts(path) { const parts = path.replaceAll('\\','/').split('/').filter(Boolean); if (!parts.length || parts.some(p => p === '.' || p === '..' || /[\x00-\x1f\x7f]/.test(p))) throw new Error('Package contains an unsafe restored path.'); return parts; }
async function restoreToDirectory(files) { if (!window.showDirectoryPicker) return false; const root = await window.showDirectoryPicker({ mode: 'readwrite' }); for (const item of files) { const parts = safeParts(item.name); let dir = root; for (const part of parts.slice(0,-1)) dir = await dir.getDirectoryHandle(part, { create: true }); const handle = await dir.getFileHandle(parts.at(-1), { create: true }); const writable = await handle.createWritable(); await writable.write(item.content); await writable.close(); } return true; }

$('encrypt').onclick = async () => {
  try {
    const files = [...$('files').files];
    if (!files.length) throw new Error('Select one or more files or a directory first.');
    const totalBytes = files.reduce((n, f) => n + f.size, 0);
    if (totalBytes > 2 * 1024 * 1024 * 1024) throw new Error('The browser vault currently limits a single package to 2 GiB.');
    const { blob, packageId } = await encryptFiles(files, $('password').value, $('pattern').value);
    downloadBlob(blob, `${packageId}.spc6`);
    $('result').textContent = `Encrypted locally. Package ID: ${packageId}`;
    log('Local encryption completed. No file content was uploaded to the server.');
  } catch (e) { log(e.message); $('result').textContent = e.message; }
};

$('decrypt').onclick = async () => {
  try {
    const file = $('package').files[0]; if (!file) throw new Error('Select a browser package first.');
    const files = await decryptFiles(file, $('password2').value, $('pattern2').value);
    const written = await restoreToDirectory(files);
    if (!written) { for (const item of files) downloadBlob(item.content, item.name.replaceAll('/','__') || 'restored-file'); }
    $('result2').textContent = written ? `${files.length} file(s) restored to the selected directory.` : `${files.length} file(s) restored as downloads. Your browser does not expose directory writing.`;
    log(`Local decryption completed for ${files.length} file(s).`);
  } catch (e) { log(e.message); $('result2').textContent = 'Unable to open the browser package.'; }
};

$('toggle1').onclick=()=>{$('password').type=$('password').type==='password'?'text':'password'};
$('toggle2').onclick=()=>{$('pattern').type=$('pattern').type==='password'?'text':'password'};
$('toggle3').onclick=()=>{$('password2').type=$('password2').type==='password'?'text':'password'};
$('toggle4').onclick=()=>{$('pattern2').type=$('pattern2').type==='password'?'text':'password'};
