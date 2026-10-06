'use strict';

const $ = (id) => document.getElementById(id);
const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

const FORMAT = 'SECURE-BROWSER-V13';
const VERSION = 13;
const MAGIC = 'SPK13BIN1';
const FOOT = 'SPK13FOOT';
const ITER = 1_500_000;
const SALT_BYTES = 32;
const IV_BYTES = 12;
const MIN = 1024 * 1024;
const TARGET = 4 * 1024 * 1024;
const MAX = 8 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_HEADER_BYTES = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 32 * 1024 * 1024;
const MAX_FILES = 100_000;
const MAX_CHUNKS = 1_000_000;
const MAX_NAME_PARTS = 256;
const MAX_NAME_BYTES = 4096;
const MAX_TOTAL_PLAIN_BYTES = 64 * 1024 * 1024 * 1024;
const SMALL = 128 * 1024 * 1024;

const S = { worker: null, pending: new Map(), seq: 0, files: [], packageId: null, sessionId: null, root: null, salt: null };

const u8 = (value) => value instanceof Uint8Array ? value : new Uint8Array(value);
const hex = (value) => [...u8(value)].map((x) => x.toString(16).padStart(2, '0')).join('');
const rnd = (length) => crypto.getRandomValues(new Uint8Array(length));
const b64 = (value) => {
  const array = u8(value);
  let output = '';
  for (let offset = 0; offset < array.length; offset += 0x8000) output += String.fromCharCode(...array.subarray(offset, offset + 0x8000));
  return btoa(output);
};
const unb64 = (value, expectedLength = null) => {
  if (typeof value !== 'string' || value.length > 16_000_000) throw new Error('Invalid encoded value.');
  let raw;
  try { raw = atob(value); } catch (_) { throw new Error('Invalid encoded value.'); }
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) output[i] = raw.charCodeAt(i);
  if (expectedLength !== null && output.length !== expectedLength) throw new Error('Invalid encoded value.');
  return output;
};
const cat = (...parts) => {
  const size = parts.reduce((sum, part) => sum + u8(part).length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    const value = u8(part);
    output.set(value, offset);
    offset += value.length;
  }
  return output;
};
const u32 = (value) => {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
};
const readU32 = (array, offset = 0) => new DataView(array.buffer, array.byteOffset + offset, 4).getUint32(0, false);

function log(message) {
  $('log').textContent = `${new Date().toLocaleTimeString()}  ${message}\n${$('log').textContent}`.slice(0, 14_000);
}

function fmt(value) {
  if (value < 1024) return `${value} B`;
  let n = value;
  let index = -1;
  const units = ['KB', 'MB', 'GB', 'TB'];
  do { n /= 1024; index += 1; } while (n >= 1024 && index < units.length - 1);
  return `${n.toFixed(n >= 10 ? 1 : 2)} ${units[index]}`;
}

function fail(message = 'Invalid V13 package.') { throw new Error(message); }

function call(op, payload = {}) {
  if (!S.worker) {
    S.worker = new Worker('client/v13/worker.js', { type: 'classic' });
    S.worker.onmessage = (event) => {
      const pending = S.pending.get(event.data.id);
      if (!pending) return;
      S.pending.delete(event.data.id);
      event.data.ok ? pending.resolve(event.data.result) : pending.reject(new Error(event.data.error));
    };
    S.worker.onerror = () => {
      for (const pending of S.pending.values()) pending.reject(new Error('Crypto worker failed.'));
      S.pending.clear();
    };
  }
  return new Promise((resolve, reject) => {
    const id = ++S.seq;
    S.pending.set(id, { resolve, reject });
    S.worker.postMessage({ id, op, ...payload });
  });
}

function safeParts(path) {
  if (typeof path !== 'string') fail('Unsafe path.');
  const parts = path.replaceAll('\\', '/').split('/').filter(Boolean);
  if (!parts.length || parts.length > MAX_NAME_PARTS) fail('Unsafe path.');
  let bytesTotal = 0;
  for (const part of parts) {
    const normalized = part.normalize('NFC');
    const encoded = te.encode(normalized);
    bytesTotal += encoded.length;
    if (
      part === '.' ||
      part === '..' ||
      /[\u0000-\u001f\u007f]/.test(part) ||
      /[\uD800-\uDFFF]/.test(part) ||
      encoded.length > 255
    ) fail('Unsafe path.');
  }
  if (bytesTotal > MAX_NAME_BYTES) fail('Path is too long.');
  return parts;
}

const FS_NAME_NOT_ALLOWED = /name is not allowed/i;
const WINDOWS_RESERVED = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/i;

function isNotFound(error) {
  return error?.name === 'NotFoundError';
}

function isNameNotAllowed(error) {
  return Boolean(error) && FS_NAME_NOT_ALLOWED.test(String(error.message || ''));
}

function utf8Trim(value, maxBytes) {
  let output = '';
  for (const char of value) {
    const next = output + char;
    if (te.encode(next).length > maxBytes) break;
    output = next;
  }
  return output || 'file';
}

async function nameDigest(value) {
  return hex(await crypto.subtle.digest('SHA-256', te.encode(value)));
}

async function compatibilityName(original, strong = false) {
  const digest = (await nameDigest(original)).slice(0, 12);
  if (strong) return `_V13_${digest}.bin`;

  let value = original.normalize('NFC');
  value = value.replace(/[\u0000-\u001f\u007f]/g, '_');
  value = value.replace(/[<>:"|?*]/g, '_');
  value = value.replace(/[. ]+$/g, '');
  if (!value) value = 'file';

  const stem = value.split('.')[0];
  if (WINDOWS_RESERVED.test(stem) || WINDOWS_RESERVED.test(value)) value = `_${value}`;
  value = utf8Trim(value, 170);

  // Chromium/Chrome may reject certain executable/script extensions at the File System Access API boundary.
  // Moving the original extension away from the final extension keeps the restored bytes intact while
  // avoiding a browser-level filename block. A cryptographic suffix prevents sanitization collisions.
  if (/\.(?:ade|adp|app|apk|appx|appxbundle|arj|asp|aspx|bat|cab|cer|chm|cmd|com|cpl|dll|dmg|exe|hta|img|ins|iso|isp|jar|jnlp|js|jse|lnk|msp|msi|msix|msixbundle|mst|nsh|ocx|ps1|reg|scr|sys|vb|vbe|vbs|vhd|vhdx|vsix|ws|wsc|wsf|wsh|xll|xla|xlam)$/i.test(value)) {
    value = `${utf8Trim(value, 150)}.v13-restore`;
  } else {
    value = `${utf8Trim(value, 170)}~v13-${digest}`;
  }
  return utf8Trim(value, 220);
}

function collisionName(name, index) {
  const dot = name.lastIndexOf('.');
  const base = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  return utf8Trim(`${base} (${index})${ext}`, 220);
}

function exactPathKey(parts) {
  return parts.map((part) => part.normalize('NFC')).join('/');
}

function physicalKey(parts) {
  return parts.map((part) => part.normalize('NFC').toLocaleLowerCase('en-US')).join('/');
}

async function probeDirectory(parent, name) {
  try {
    return await parent.getDirectoryHandle(name, { create: true });
  } catch (error) {
    if (isNameNotAllowed(error)) return null;
    throw error;
  }
}

async function probeFile(parent, name) {
  let handle = null;
  let writable = null;
  try {
    handle = await parent.getFileHandle(name, { create: true });
    writable = await handle.createWritable();
    await writable.close();
    writable = null;
    await parent.removeEntry(name);
    return true;
  } catch (error) {
    try { await writable?.close(); } catch (_) {}
    if (handle) await parent.removeEntry(name).catch(() => {});
    if (isNameNotAllowed(error)) return false;
    throw error;
  }
}

async function probePhysicalPath(root, outputFiles) {
  const probeName = `.__secure-v13-probe-${[...rnd(8)].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
  const probeRoot = await root.getDirectoryHandle(probeName, { create: true });
  const directoryChoices = new Map();
  const usedDirectoryNames = new Map();
  const usedFileNames = new WeakMap();

  const uniqueCandidate = (base, used) => {
    if (!used.has(base.toLocaleLowerCase('en-US'))) return base;
    for (let index = 1; index <= 100_000; index += 1) {
      const candidate = collisionName(base, index);
      if (!used.has(candidate.toLocaleLowerCase('en-US'))) return candidate;
    }
    fail('Unable to choose a unique compatible restore name.');
  };

  try {
    for (const output of outputFiles) {
      let probeDir = probeRoot;
      const physical = [];

      for (let i = 0; i < output.safe.length - 1; i += 1) {
        const sourcePrefix = exactPathKey(output.safe.slice(0, i + 1));
        const parentPrefix = exactPathKey(output.safe.slice(0, i));
        let choice = directoryChoices.get(sourcePrefix);
        if (!choice) {
          const used = usedDirectoryNames.get(parentPrefix) || new Set();
          usedDirectoryNames.set(parentPrefix, used);
          let candidate = uniqueCandidate(output.safe[i], used);
          let directory = await probeDirectory(probeDir, candidate);
          if (!directory) {
            candidate = uniqueCandidate(await compatibilityName(output.safe[i]), used);
            directory = await probeDirectory(probeDir, candidate);
            if (!directory) {
              candidate = uniqueCandidate(await compatibilityName(output.safe[i], true), used);
              directory = await probeDirectory(probeDir, candidate);
              if (!directory) fail('This browser cannot create a compatible restore directory name.');
            }
            choice = { name: candidate, directory, adapted: true };
          } else {
            choice = { name: candidate, directory, adapted: candidate !== output.safe[i] };
          }
          used.add(candidate.toLocaleLowerCase('en-US'));
          directoryChoices.set(sourcePrefix, choice);
        }
        probeDir = choice.directory;
        physical.push(choice.name);
      }

      let used = usedFileNames.get(probeDir);
      if (!used) { used = new Set(); usedFileNames.set(probeDir, used); }
      let candidate = uniqueCandidate(output.safe.at(-1), used);
      let ok = await probeFile(probeDir, candidate);
      if (!ok) {
        candidate = uniqueCandidate(await compatibilityName(output.safe.at(-1)), used);
        ok = await probeFile(probeDir, candidate);
        if (!ok) {
          candidate = uniqueCandidate(await compatibilityName(output.safe.at(-1), true), used);
          ok = await probeFile(probeDir, candidate);
        }
      }
      if (!ok) fail('This browser cannot create a compatible restore filename.');
      used.add(candidate.toLocaleLowerCase('en-US'));
      physical.push(candidate);
      output.physical = physical;
      output.preflightAdapted = physical.some((part, index) => part !== output.safe[index]);
    }
  } finally {
    await root.removeEntry(probeName, { recursive: true }).catch(() => {});
  }
}

async function restorePathState(parent, name) {
  try {
    await parent.getDirectoryHandle(name, { create: false });
    return 'directory';
  } catch (error) {
    if (isNameNotAllowed(error)) return 'blocked';
    if (error?.name !== 'TypeMismatchError' && !isNotFound(error)) throw error;
  }
  try {
    await parent.getFileHandle(name, { create: false });
    return 'file';
  } catch (error) {
    if (isNameNotAllowed(error)) return 'blocked';
    if (isNotFound(error)) return 'missing';
    throw error;
  }
}

async function resolveActualRestorePaths(root, outputFiles) {
  const directoryCache = new Map();
  const usedByDirectory = new WeakMap();
  const createdDirectories = [];
  const actualPaths = [];

  const usedSet = (dir) => {
    let used = usedByDirectory.get(dir);
    if (!used) { used = new Set(); usedByDirectory.set(dir, used); }
    return used;
  };



  const chooseAvailable = async (parent, desired, used, forceSafe = false) => {
    let candidate = forceSafe ? await compatibilityName(desired, true) : desired;
    for (let index = 0; index <= 100_000; index += 1) {
      const candidateKey = candidate.toLocaleLowerCase('en-US');
      if (!used.has(candidateKey)) {
        const state = await restorePathState(parent, candidate);
        if (state === 'missing') {
          if (await probeFile(parent, candidate)) return candidate;
          if (!forceSafe) return chooseAvailable(parent, desired, used, true);
        }
      }
      candidate = collisionName(candidate, Math.max(1, index + 1));
    }
    fail('Unable to choose a non-conflicting restore path.');
  };

  try {
    for (const output of outputFiles) {
      let dir = root;
      const actualDirs = [];
      for (let i = 0; i < output.physical.length - 1; i += 1) {
        const sourcePrefix = exactPathKey(output.safe.slice(0, i + 1));
        const cached = directoryCache.get(sourcePrefix);
        if (cached) {
          dir = cached.dir;
          actualDirs.push(cached.name);
          continue;
        }

        const used = usedSet(dir);
        let desired = output.physical[i];
        let state = used.has(desired.toLocaleLowerCase('en-US')) ? 'package-collision' : await restorePathState(dir, desired);
        let name = desired;
        let child = null;

        if (state === 'directory' && desired === output.safe[i]) {
          child = await dir.getDirectoryHandle(name, { create: false });
        } else {
          if (state === 'blocked' || state === 'file' || state === 'package-collision' || state === 'directory') {
            name = await chooseAvailable(dir, desired, used, true);
          } else {
            try {
              child = await dir.getDirectoryHandle(name, { create: true });
              createdDirectories.push({ parent: dir, name });
            } catch (error) {
              if (!isNameNotAllowed(error) && error?.name !== 'TypeMismatchError') throw error;
              name = await chooseAvailable(dir, desired, used, true);
            }
          }
          if (!child) child = await dir.getDirectoryHandle(name, { create: true });
        }

        used.add(name.toLocaleLowerCase('en-US'));
        directoryCache.set(sourcePrefix, { name, dir: child });
        dir = child;
        actualDirs.push(name);
      }

      const used = usedSet(dir);
      let desired = output.physical.at(-1);
      let state = await restorePathState(dir, desired);
      let name = desired;
      if (state !== 'missing') name = await chooseAvailable(dir, desired, used, state === 'blocked');
      else if (!(await probeFile(dir, name))) name = await chooseAvailable(dir, desired, used, true);
      used.add(name.toLocaleLowerCase('en-US'));
      output.actualPhysical = [...actualDirs, name];
      actualPaths.push(output);
    }
  } catch (error) {
    for (let i = createdDirectories.length - 1; i >= 0; i -= 1) {
      const created = createdDirectories[i];
      await created.parent.removeEntry(created.name).catch(() => {});
    }
    throw error;
  }

  return actualPaths.reduce((count, output) => count + (output.actualPhysical.some((part, index) => part !== output.safe[index]) ? 1 : 0), 0);
}

function validateSecrets(password, pattern) {
  if (typeof password !== 'string' || typeof pattern !== 'string' || new Blob([password]).size > 4096 || new Blob([pattern]).size > 4096) fail('Credential material is invalid.');
  if (password.length < 14 || pattern.length < 14) fail('Password and pattern must contain at least 14 characters.');
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^\p{L}\p{N}]/u.test(password)) fail('Password requires lowercase, uppercase, numeric and special characters.');
  if (new Set([...pattern]).size < 6) fail('Pattern is too repetitive.');
}

function assertHeader(header) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail();
  if (header.format !== FORMAT || header.version !== VERSION || header.container !== MAGIC || header.server_plaintext !== false || header.streaming !== true || header.kdf !== 'PBKDF2-HMAC-SHA-256') fail();
  if (typeof header.package_id !== 'string' || !/^[a-f0-9]{48}$/.test(header.package_id)) fail();
  if (typeof header.iterations !== 'number' || header.iterations !== ITER || !Number.isSafeInteger(header.iterations)) fail();
  const salt = unb64(header.salt, SALT_BYTES);
  if (!header.chunking || header.chunking.algorithm !== 'content-defined-streaming' || header.chunking.min !== MIN || header.chunking.target !== TARGET || header.chunking.max !== MAX) fail();
  if (!header.key_slots || typeof header.key_slots.primary !== 'object') fail();
  if (!header.manifest_iv) fail();
  unb64(header.manifest_iv, IV_BYTES);
  const primary = header.key_slots.primary;
  if (primary.type !== 'password-pattern' || primary.version !== 1) fail();
  unb64(primary.iv, IV_BYTES);
  if (unb64(primary.value).length !== 48) fail();
  if (header.key_slots.recovery !== null && header.key_slots.recovery !== undefined) {
    const recovery = header.key_slots.recovery;
    if (recovery.type !== 'recovery' || recovery.version !== 1) fail();
    unb64(recovery.iv, IV_BYTES);
    if (unb64(recovery.value).length !== 48) fail();
  }
  return salt;
}

async function hash(value) { return u8(await call('hash', { data: u8(value) })); }

class MerkleAccumulator {
  constructor() { this.levels = []; this.count = 0; }
  async push(leafHex) {
    let carry = unhex(leafHex);
    let level = 0;
    while (this.levels[level]) {
      carry = u8(await hash(cat(te.encode('SecurePackage|V13|NODE|'), this.levels[level], carry)));
      this.levels[level] = null;
      level += 1;
    }
    this.levels[level] = carry;
    this.count += 1;
  }
  async root() {
    if (this.count === 0) return hex(await hash(te.encode('SecurePackage|V13|EMPTY')));
    let carry = null;
    for (let i = 0; i < this.levels.length; i += 1) {
      const levelValue = this.levels[i];
      if (!levelValue) continue;
      carry = carry === null
        ? levelValue
        : u8(await hash(cat(te.encode('SecurePackage|V13|NODE|'), levelValue, carry)));
    }
    return hex(carry);
  }
}

async function* cdc(file) {
  const reader = file.stream().getReader();
  let parts = [];
  let size = 0;
  let rolling = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const array = u8(value);
    let start = 0;
    for (let i = 0; i < array.length; i += 1) {
      rolling = ((rolling << 5) ^ array[i]) >>> 0;
      const current = size + i - start + 1;
      if (current >= MIN && ((rolling & (TARGET - 1)) === 0 || current >= MAX)) {
        parts.push(array.subarray(start, i + 1));
        yield cat(...parts);
        parts = [];
        size = 0;
        rolling = 0;
        start = i + 1;
      }
    }
    if (start < array.length) {
      parts.push(array.subarray(start));
      size += array.length - start;
    }
  }
  if (size || file.size === 0) yield cat(...parts);
}

class BlobWriter {
  constructor() { this.parts = []; this.size = 0; }
  async write(value) { this.parts.push(value); this.size += u8(value).length; }
  async close() { return new Blob(this.parts, { type: 'application/octet-stream' }); }
}

async function openWriter(total) {
  if (total > MAX_PACKAGE_BYTES) fail('Package exceeds the V13 size limit.');
  if (window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({
      suggestedName: `${S.packageId}.spk13`,
      types: [{ description: 'Secure Package V13', accept: { 'application/octet-stream': ['.spk13'] } }],
    });
    return { kind: 'file', writer: await handle.createWritable() };
  }
  if (total > SMALL) fail('Large packages require the File System Access API in this browser.');
  return { kind: 'blob', writer: new BlobWriter() };
}

async function checkpoint(state) {
  try {
    const request = indexedDB.open('secure-package-v13', 1);
    await new Promise((resolve, reject) => {
      request.onupgradeneeded = () => request.result.createObjectStore('build', { keyPath: 'id' });
      request.onsuccess = () => {
        const tx = request.result.transaction('build', 'readwrite');
        tx.objectStore('build').put({ id: 'active', state, time: Date.now() });
        tx.oncomplete = resolve;
        tx.onerror = reject;
      };
      request.onerror = reject;
    });
  } catch (_) { /* Checkpointing is optional and stores no secrets. */ }
}

async function clearCheckpoint() {
  try {
    const request = indexedDB.open('secure-package-v13', 1);
    await new Promise((resolve, reject) => {
      request.onsuccess = () => {
        const tx = request.result.transaction('build', 'readwrite');
        tx.objectStore('build').delete('active');
        tx.oncomplete = resolve;
        tx.onerror = reject;
      };
      request.onerror = reject;
    });
  } catch (_) { /* Best effort. */ }
}

async function build(files, password, pattern, makeRecovery) {
  validateSecrets(password, pattern);
  if (!Number.isInteger(files.length) || files.length < 1 || files.length > MAX_FILES) fail('Too many files.');
  const total = files.reduce((sum, file) => {
    if (!Number.isSafeInteger(file.size) || file.size < 0) fail('Invalid file size.');
    if (file.size > 16 * 1024 * 1024 * 1024) fail('A file exceeds the V13 size limit.');
    return sum + file.size;
  }, 0);
  if (!Number.isSafeInteger(total) || total > MAX_TOTAL_PLAIN_BYTES) fail('Package exceeds the V13 plaintext limit.');

  S.packageId = hex(rnd(24));
  S.salt = rnd(SALT_BYTES);
  S.root = rnd(32);
  const primary = await call('wrapCredential', { password, pattern, root: S.root, salt: S.salt, iterations: ITER, packageId: S.packageId });
  const recoveryKey = makeRecovery ? hex(rnd(32)) : null;
  const recoverySlot = recoveryKey ? await call('wrapRecovery', { recovery: recoveryKey, root: S.root, salt: S.salt, iterations: ITER, packageId: S.packageId }) : null;
  S.sessionId = (await call('createSession', { password, pattern, root: S.root, salt: S.salt, iterations: ITER })).sessionId;

  const manifestIv = await call('nonce', { sessionId: S.sessionId, context: `${S.packageId}|manifest` });
  const header = {
    format: FORMAT,
    version: VERSION,
    container: MAGIC,
    package_id: S.packageId,
    salt: b64(S.salt),
    kdf: 'PBKDF2-HMAC-SHA-256',
    iterations: ITER,
    chunking: { algorithm: 'content-defined-streaming', min: MIN, target: TARGET, max: MAX },
    key_slots: {
      primary: { type: 'password-pattern', version: 1, ...primary },
      recovery: recoverySlot ? { type: 'recovery', version: 1, ...recoverySlot } : null,
    },
    manifest_iv: b64(manifestIv),
    server_plaintext: false,
    streaming: true,
  };
  const manifest = { format: FORMAT, version: VERSION, package_id: S.packageId, files: [], chunks: [], merkle_root: null, chunking: header.chunking };
  const merkle = new MerkleAccumulator();
  let writer;
  let done = 0;
  let physicalBytes = 0;

  try {
    writer = await openWriter(total + Math.ceil(total * 0.08) + MAX_HEADER_BYTES);
    const headerBytes = te.encode(JSON.stringify(header));
    if (headerBytes.length > MAX_HEADER_BYTES) fail('Header exceeds V13 limits.');
    await writer.writer.write(cat(te.encode(`${MAGIC}\n`), u32(headerBytes.length), headerBytes));
    physicalBytes = 10 + 4 + headerBytes.length;

    for (const file of files) {
      const path = safeParts(file.webkitRelativePath || file.name);
      const id = hex(rnd(16));
      const entry = { id, size: file.size, path_parts: [], chunks: [] };
      for (let i = 0; i < path.length; i += 1) {
        const iv = await call('nonce', { sessionId: S.sessionId, context: `${S.packageId}|name|${id}|${i}` });
        const cipher = await call('crypt', {
          sessionId: S.sessionId,
          purpose: 'filename',
          context: `name|${id}|${i}`,
          mode: 'enc',
          iv,
          data: te.encode(path[i].normalize('NFC')),
          aad: `${FORMAT}|${S.packageId}|name|${id}|${i}`,
        });
        entry.path_parts.push({ iv: b64(iv), value: b64(cipher) });
      }

      let index = 0;
      for await (const plain of cdc(file)) {
        if (manifest.chunks.length >= MAX_CHUNKS) fail('Too many encrypted chunks.');
        const iv = await call('nonce', { sessionId: S.sessionId, context: `${S.packageId}|file|${id}|${index}` });
        const cipher = await call('crypt', {
          sessionId: S.sessionId,
          purpose: 'file',
          context: `file|${id}`,
          mode: 'enc',
          iv,
          data: plain,
          aad: `${FORMAT}|${S.packageId}|file|${id}|${index}`,
        });
        const cipherBytes = u8(cipher);
        const meta = { id: hex(await hash(cipherBytes)), file_id: id, index, plain_size: plain.length, cipher_size: cipherBytes.length, iv: b64(iv) };
        if (meta.cipher_size !== meta.plain_size + 16) fail('Ciphertext length invariant failed.');
        const leaf = hex(await hash(cat(te.encode('SecurePackage|V13|LEAF|'), te.encode(JSON.stringify(meta)), cipherBytes)));
        const metaBytes = te.encode(JSON.stringify(meta));
        await writer.writer.write(cat(u32(metaBytes.length), metaBytes, u32(cipherBytes.length), cipherBytes));
        manifest.chunks.push(meta);
        entry.chunks.push(meta.id);
        await merkle.push(leaf);
        physicalBytes += 4 + metaBytes.length + 4 + cipherBytes.length;
        if (physicalBytes > MAX_PACKAGE_BYTES) fail('Package exceeds the V13 size limit.');
        index += 1;
        done += plain.length;
        const percent = Math.min(99, Math.round(done / Math.max(total, 1) * 100));
        $('progressBar').style.width = `${percent}%`;
        $('progressText').textContent = `${percent}% · ${fmt(done)} / ${fmt(total)}`;
        await checkpoint({ packageId: S.packageId, bytes: done, records: manifest.chunks.length, filesCompleted: manifest.files.length });
      }
      if (done < manifest.files.reduce((sum, x) => sum + x.size, 0)) fail('Internal build size invariant failed.');
      manifest.files.push(entry);
    }

    manifest.merkle_root = await merkle.root();
    const manifestPlain = te.encode(JSON.stringify(manifest));
    if (manifestPlain.length > MAX_MANIFEST_BYTES) fail('Manifest exceeds the V13 limit.');
    const manifestCipher = await call('crypt', { sessionId: S.sessionId, purpose: 'manifest', context: 'manifest', mode: 'enc', iv: manifestIv, data: manifestPlain, aad: `${FORMAT}|${S.packageId}|manifest|${VERSION}` });
    const manifestCipherBytes = u8(manifestCipher);
    await writer.writer.write(cat(manifestCipherBytes, u32(manifestCipherBytes.length), te.encode(FOOT)));
    physicalBytes += manifestCipherBytes.length + 13;
    if (physicalBytes > MAX_PACKAGE_BYTES) fail('Package exceeds the V13 size limit.');

    const blob = writer.kind === 'file' ? (await writer.writer.close(), null) : await writer.writer.close();
    await clearCheckpoint();
    $('progressBar').style.width = '100%';
    $('progressText').textContent = '100%';
    return { blob, packageId: S.packageId, recoveryKey };
  } finally {
    if (S.sessionId) await call('destroy', { sessionId: S.sessionId }).catch(() => {});
    S.sessionId = null;
    if (S.root) S.root.fill(0);
    S.root = null;
    S.salt = null;
  }
}

function unhex(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]+$/i.test(value) || value.length % 2 !== 0) fail();
  const output = new Uint8Array(value.length / 2);
  for (let i = 0; i < output.length; i += 1) output[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return output;
}

async function readHeader(file) {
  if (!Number.isSafeInteger(file.size) || file.size < 14 || file.size > MAX_PACKAGE_BYTES) fail('Package size is invalid.');
  const prefix = u8(await file.slice(0, 14).arrayBuffer());
  if (td.decode(prefix.slice(0, 10)) !== `${MAGIC}\n`) fail('Unsupported V13 package.');
  const length = readU32(prefix, 10);
  if (length < 2 || length > MAX_HEADER_BYTES || 14 + length > file.size) fail('Invalid V13 header.');
  let header;
  try { header = JSON.parse(td.decode(u8(await file.slice(14, 14 + length).arrayBuffer()))); } catch (_) { fail(); }
  const salt = assertHeader(header);
  return { header, offset: 14 + length, salt };
}

async function readFooter(file) {
  if (file.size < 13 || file.size > MAX_PACKAGE_BYTES) fail('Package size is invalid.');
  const trailer = u8(await file.slice(file.size - 13).arrayBuffer());
  if (td.decode(trailer.slice(4)) !== FOOT) fail('Missing V13 footer.');
  const length = readU32(trailer, 0);
  if (length < 17 || length > MAX_MANIFEST_BYTES + 16 || file.size < length + 13) fail('Invalid V13 footer.');
  const start = file.size - length - 13;
  if (start < 14 || start > file.size - 13) fail();
  return { start, cipher: u8(await file.slice(start, start + length).arrayBuffer()) };
}

function validateManifest(manifest, packageId) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) fail();
  if (manifest.format !== FORMAT || manifest.version !== VERSION || manifest.package_id !== packageId) fail();
  if (!Array.isArray(manifest.files) || !Array.isArray(manifest.chunks) || manifest.files.length < 1 || manifest.files.length > MAX_FILES || manifest.chunks.length < 1 || manifest.chunks.length > MAX_CHUNKS) fail();
  const fileIds = new Set();
  const chunkIds = new Set();
  const chunkMap = new Map();
  let totalPlain = 0;
  for (const file of manifest.files) {
    if (!file || typeof file.id !== 'string' || !/^[a-f0-9]{32}$/.test(file.id) || fileIds.has(file.id) || !Number.isSafeInteger(file.size) || file.size < 0) fail();
    fileIds.add(file.id);
    if (!Array.isArray(file.path_parts) || file.path_parts.length < 1 || file.path_parts.length > MAX_NAME_PARTS || !Array.isArray(file.chunks) || file.chunks.length > MAX_CHUNKS) fail();
    let pathBytes = 0;
    for (const part of file.path_parts) {
      if (!part || typeof part.iv !== 'string' || typeof part.value !== 'string') fail();
      unb64(part.iv, IV_BYTES);
      const value = unb64(part.value);
      if (value.length < 17 || value.length > 271) fail();
      pathBytes += value.length - 16;
    }
    if (pathBytes < 1 || pathBytes > MAX_NAME_BYTES) fail();
    totalPlain += file.size;
    if (totalPlain > MAX_TOTAL_PLAIN_BYTES) fail();
    for (const chunkId of file.chunks) {
      if (typeof chunkId !== 'string' || !/^[a-f0-9]{64}$/.test(chunkId)) fail();
    }
  }
  for (const chunk of manifest.chunks) {
    if (!chunk || typeof chunk.id !== 'string' || !/^[a-f0-9]{64}$/.test(chunk.id) || chunkIds.has(chunk.id)) fail();
    if (typeof chunk.file_id !== 'string' || !fileIds.has(chunk.file_id) || !Number.isSafeInteger(chunk.index) || chunk.index < 0 || chunk.index >= MAX_CHUNKS) fail();
    if (!Number.isSafeInteger(chunk.plain_size) || chunk.plain_size < 0 || chunk.plain_size > MAX || !Number.isSafeInteger(chunk.cipher_size) || chunk.cipher_size !== chunk.plain_size + 16) fail();
    unb64(chunk.iv, IV_BYTES);
    chunkIds.add(chunk.id);
    chunkMap.set(chunk.id, chunk);
  }
  const referenced = new Set();
  for (const file of manifest.files) {
    if (file.size === 0 && file.chunks.length !== 1) fail();
    let fileTotal = 0;
    for (let i = 0; i < file.chunks.length; i += 1) {
      const id = file.chunks[i];
      if (referenced.has(id)) fail('Chunk referenced more than once.');
      referenced.add(id);
      const chunk = chunkMap.get(id);
      if (!chunk || chunk.file_id !== file.id || chunk.index !== i) fail('Manifest chunk ordering is invalid.');
      if (chunk.plain_size === 0 && !(file.size === 0 && i === 0 && file.chunks.length === 1)) fail('Invalid empty chunk.');
      fileTotal += chunk.plain_size;
    }
    if (fileTotal !== file.size) fail('Manifest file size mismatch.');
  }
  if (referenced.size !== manifest.chunks.length) fail('Manifest contains unreachable chunks.');
  if (typeof manifest.merkle_root !== 'string' || !/^[a-f0-9]{64}$/.test(manifest.merkle_root)) fail();
  return manifest;
}

function canonicalMeta(meta) {
  return {
    id: meta.id,
    file_id: meta.file_id,
    index: meta.index,
    plain_size: meta.plain_size,
    cipher_size: meta.cipher_size,
    iv: meta.iv,
  };
}

async function readInventory(file, start, end) {
  const index = new Map();
  let offset = start;
  let physical = 0;
  while (offset < end) {
    if (end - offset < 8) fail('Truncated chunk record.');
    const metaLength = readU32(u8(await file.slice(offset, offset + 4).arrayBuffer()));
    offset += 4;
    if (metaLength < 2 || metaLength > 1024 * 1024 || offset + metaLength > end) fail('Invalid record metadata.');
    let meta;
    try { meta = JSON.parse(td.decode(u8(await file.slice(offset, offset + metaLength).arrayBuffer()))); } catch (_) { fail(); }
    offset += metaLength;
    if (end - offset < 4) fail('Truncated chunk record.');
    const cipherLength = readU32(u8(await file.slice(offset, offset + 4).arrayBuffer()));
    offset += 4;
    if (cipherLength < 16 || cipherLength > MAX + 16 || offset + cipherLength > end) fail('Invalid chunk ciphertext.');
    if (!meta || typeof meta.id !== 'string' || !/^[a-f0-9]{64}$/.test(meta.id) || index.has(meta.id)) fail('Invalid chunk inventory.');
    const expectedMetaKeys = ['cipher_size', 'file_id', 'id', 'index', 'iv', 'plain_size'];
    if (JSON.stringify(Object.keys(meta).sort()) !== JSON.stringify(expectedMetaKeys)) fail('Invalid chunk metadata.');
    if (!Number.isSafeInteger(meta.index) || meta.index < 0 || meta.index >= MAX_CHUNKS || typeof meta.file_id !== 'string' || !/^[a-f0-9]{32}$/.test(meta.file_id)) fail();
    if (!Number.isSafeInteger(meta.plain_size) || meta.plain_size < 0 || meta.plain_size > MAX || meta.cipher_size !== cipherLength || meta.cipher_size !== meta.plain_size + 16) fail();
    unb64(meta.iv, IV_BYTES);
    index.set(meta.id, { meta, offset, length: cipherLength });
    offset += cipherLength;
    physical += 8 + metaLength + cipherLength;
    if (index.size > MAX_CHUNKS || physical > MAX_PACKAGE_BYTES) fail('Package inventory exceeds limits.');
  }
  if (offset !== end) fail();
  return index;
}

async function verifyInventory(file, inventory, manifest) {
  if (inventory.size !== manifest.chunks.length) fail('Chunk count mismatch.');
  const merkle = new MerkleAccumulator();
  for (const expected of manifest.chunks) {
    const record = inventory.get(expected.id);
    if (!record) fail('Chunk inventory does not match the manifest.');
    if (JSON.stringify(canonicalMeta(record.meta)) !== JSON.stringify(canonicalMeta(expected))) fail('Chunk metadata mismatch.');
    const cipher = u8(await file.slice(record.offset, record.offset + record.length).arrayBuffer());
    if (hex(await hash(cipher)) !== expected.id) fail('Chunk integrity failure.');
    await merkle.push(hex(await hash(cat(te.encode('SecurePackage|V13|LEAF|'), te.encode(JSON.stringify(canonicalMeta(record.meta))), cipher))));
  }
  const root = await merkle.root();
  if (!crypto.subtle || root !== manifest.merkle_root) fail('Merkle integrity verification failed.');
  return true;
}

async function restore(file, password, pattern, recovery, root) {
  if (/\.spkg14$/i.test(file.name || '')) fail('V14 server packages (.spkg14) are not compatible with Browser Vault V13. Open them in the V14 server workspace.');
  if (!root) fail('A restore destination was not selected.');
  const { header, offset, salt } = await readHeader(file);
  const footer = await readFooter(file);
  if (footer.start <= offset) fail('Package contains no encrypted records.');
  const plainManifest = recovery
    ? await call('unlockRecovery', { recovery, salt, iterations: ITER, slot: header.key_slots.recovery, packageId: header.package_id })
    : await call('unlock', {
        password,
        pattern,
        salt,
        iterations: ITER,
        slot: header.key_slots.primary,
        packageId: header.package_id,
      });
  const sid = plainManifest.sessionId;
  try {
    const manifestPlain = await call('crypt', { sessionId: sid, purpose: 'manifest', context: 'manifest', mode: 'dec', iv: unb64(header.manifest_iv, IV_BYTES), data: footer.cipher, aad: `${FORMAT}|${header.package_id}|manifest|${VERSION}` });
    if (manifestPlain.length > MAX_MANIFEST_BYTES) fail('Manifest is too large.');
    let manifest;
    try { manifest = JSON.parse(td.decode(manifestPlain)); } catch (_) { fail(); }
    validateManifest(manifest, header.package_id);
    const inventory = await readInventory(file, offset, footer.start);
    await verifyInventory(file, inventory, manifest);

    const outputPaths = new Set();
    const outputFiles = [];
    for (const fileEntry of manifest.files) {
      const names = [];
      for (let i = 0; i < fileEntry.path_parts.length; i += 1) {
        const part = fileEntry.path_parts[i];
        const plain = await call('crypt', {
          sessionId: sid,
          purpose: 'filename',
          context: `name|${fileEntry.id}|${i}`,
          mode: 'dec',
          iv: unb64(part.iv, IV_BYTES),
          data: unb64(part.value),
          aad: `${FORMAT}|${header.package_id}|name|${fileEntry.id}|${i}`,
        });
        names.push(td.decode(plain));
      }
      const safe = safeParts(names.join('/'));
      const normalizedKey = exactPathKey(safe);
      if (outputPaths.has(normalizedKey)) fail('Duplicate restored path.');
      outputPaths.add(normalizedKey);
      outputFiles.push({ fileEntry, safe, physical: null });
    }

    const outputPathList = [...outputPaths].sort();
    for (let i = 1; i < outputPathList.length; i += 1) {
      const previous = outputPathList[i - 1];
      const current = outputPathList[i];
      if (current.startsWith(`${previous}/`)) fail('Package contains a file/directory path conflict.');
    }

    await probePhysicalPath(root, outputFiles);
    const adaptedCount = await resolveActualRestorePaths(root, outputFiles);

    $('state').textContent = 'RESTORING';

    let total = 0;
    for (const { fileEntry, actualPhysical } of outputFiles) {
      let dir = root;
      for (let i = 0; i < actualPhysical.length - 1; i += 1) {
        const part = actualPhysical[i];
        try {
          dir = await dir.getDirectoryHandle(part, { create: true });
        } catch (error) {
          if (!isNameNotAllowed(error)) throw error;
          const fallback = await compatibilityName(part, true);
          dir = await dir.getDirectoryHandle(fallback, { create: true });
        }
      }

      let fileName = actualPhysical.at(-1);
      let handle;
      const currentState = await restorePathState(dir, fileName);
      if (currentState !== 'missing') {
        fileName = await chooseAvailable(dir, fileName, new Set(), currentState === 'blocked');
        actualPhysical[actualPhysical.length - 1] = fileName;
      }
      try {
        handle = await dir.getFileHandle(fileName, { create: true });
      } catch (error) {
        if (!isNameNotAllowed(error)) throw error;
        fileName = await compatibilityName(fileName, true);
        actualPhysical[actualPhysical.length - 1] = fileName;
        handle = await dir.getFileHandle(fileName, { create: true });
      }

      const writable = await handle.createWritable();
      try {
        let fileTotal = 0;
        for (let i = 0; i < fileEntry.chunks.length; i += 1) {
          const recordId = fileEntry.chunks[i];
          const record = inventory.get(recordId);
          if (!record || record.meta.file_id !== fileEntry.id || record.meta.index !== i) fail('Chunk mapping is invalid.');
          const cipher = u8(await file.slice(record.offset, record.offset + record.length).arrayBuffer());
          const plain = await call('crypt', {
            sessionId: sid,
            purpose: 'file',
            context: `file|${fileEntry.id}`,
            mode: 'dec',
            iv: unb64(record.meta.iv, IV_BYTES),
            data: cipher,
            aad: `${FORMAT}|${header.package_id}|file|${fileEntry.id}|${i}`,
          });
          fileTotal += plain.length;
          total += plain.length;
          if (fileTotal > fileEntry.size || total > MAX_TOTAL_PLAIN_BYTES) fail('Restore size limit exceeded.');
          await writable.write(plain);
          $('progressText').textContent = `Restoring · ${fmt(total)}`;
        }
        if (fileTotal !== fileEntry.size) fail('Restored file size mismatch.');
      } finally {
        await writable.close();
      }
    }
    const finalAdaptedCount = outputFiles.reduce((count, output) => count + (output.actualPhysical.some((part, index) => part !== output.safe[index]) ? 1 : 0), 0);
    return { count: manifest.files.length, adaptedCount: finalAdaptedCount };
  } finally {
    await call('destroy', { sessionId: sid }).catch(() => {});
  }
}

function select(files) {
  S.files = [...files];
  if (S.files.length > MAX_FILES) { S.files = []; fail('Too many files selected.'); }
  const total = S.files.reduce((sum, file) => sum + file.size, 0);
  $('fileCount').textContent = S.files.length;
  $('totalSize').textContent = fmt(total);
  $('selection').textContent = S.files.slice(0, 5).map((file) => file.webkitRelativePath || file.name).join(' · ') + (S.files.length > 5 ? ' …' : '');
  $('build').disabled = !S.files.length;
  log(`Selected ${S.files.length} file(s), ${fmt(total)}.`);
}

$('browse').onclick = () => $('files').click();
$('files').onchange = () => { try { select($('files').files); } catch (error) { $('result').textContent = error.message; } };
$('drop').ondragover = (event) => { event.preventDefault(); $('drop').classList.add('active'); };
$('drop').ondragleave = () => $('drop').classList.remove('active');
$('drop').ondrop = (event) => { event.preventDefault(); $('drop').classList.remove('active'); try { select(event.dataTransfer.files); } catch (error) { $('result').textContent = error.message; } };

$('build').onclick = async () => {
  try {
    if (!S.files.length) fail('Select files first.');
    $('build').disabled = true;
    $('state').textContent = 'STREAMING';
    const result = await build(S.files, $('password').value, $('pattern').value, $('recovery').checked);
    if (result.blob) {
      const anchor = document.createElement('a');
      const url = URL.createObjectURL(result.blob);
      anchor.href = url;
      anchor.download = `${result.packageId}.spk13`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    }
    $('result').textContent = result.recoveryKey
      ? `Created ${result.packageId}. Recovery key: ${result.recoveryKey} — save it offline; it will not be shown again.`
      : `Created ${result.packageId}.`;
    $('password').value = '';
    $('pattern').value = '';
    log('V13 package built locally with bounded-memory streaming and authenticated Merkle verification metadata.');
    $('state').textContent = 'READY';
  } catch (error) {
    $('state').textContent = 'ERROR';
    $('result').textContent = error.message;
    log(error.message);
  } finally { $('build').disabled = !S.files.length; }
};

$('decrypt').onclick = async () => {
  let root = null;
  try {
    const file = $('package').files[0];
    if (!file) fail('Select a .spk13 package.');
    if (/\.spkg14$/i.test(file.name || '')) fail('V14 server packages (.spkg14) are not compatible with Browser Vault V13. Open them in the V14 server workspace.');
    if (!window.showDirectoryPicker) fail('Directory restore is unavailable in this browser or security context. Use a current Chrome/Edge browser over HTTPS or localhost.');

    $('decrypt').disabled = true;
    $('state').textContent = 'SELECT DESTINATION';

    // The picker must run immediately inside the click activation; doing crypto awaits first can make browsers reject it.
    try {
      root = await showDirectoryPicker({ mode: 'readwrite' });
    } catch (error) {
      if (error?.name === 'AbortError') {
        $('decryptResult').textContent = 'Restore cancelled. No files were changed.';
        $('state').textContent = 'READY';
        log('Restore cancelled; no files were changed.');
        return;
      }
      throw error;
    }

    $('state').textContent = 'VERIFYING';
    const result = await restore(file, $('decryptPassword').value, $('decryptPattern').value, $('recoveryKey').value.trim(), root);
    $('decryptPassword').value = '';
    $('decryptPattern').value = '';
    $('recoveryKey').value = '';
    $('decryptResult').textContent = result.adaptedCount
      ? `${result.count} file(s) restored locally. ${result.adaptedCount} path name(s) were adjusted for browser/filesystem compatibility; no data was overwritten.`
      : `${result.count} file(s) restored locally. No existing data was overwritten.`;
    $('state').textContent = 'READY';
    log(result.adaptedCount
      ? `V13 package authenticated and restored. ${result.adaptedCount} incompatible path name(s) were mapped to safe local names without overwriting existing data.`
      : 'V13 package authenticated, Merkle-verified, then restored without overwriting existing paths.');
  } catch (error) {
    const message = isNameNotAllowed(error)
      ? 'The browser rejected a restore filename. The package was not overwritten; retrying after a page refresh may be required if an old client is cached.'
      : (error?.message || 'Unable to open or restore the package.');
    $('decryptResult').textContent = message;
    $('state').textContent = 'ERROR';
    log(message);
  } finally { $('decrypt').disabled = false; }
};

$('clear').onclick = () => $('log').textContent = 'Security console cleared.';

async function apiCsrf() {
  const response = await fetch('api-v13.php?action=csrf', { credentials: 'same-origin', cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok || !payload.ok || typeof payload.csrf !== 'string') fail('Unable to initialize secure transport.');
  return payload.csrf;
}

async function uploadPackage(file) {
  if (file.size > MAX_PACKAGE_BYTES) fail('Package exceeds the V13 size limit.');
  const { header, offset } = await readHeader(file);
  const footer = await readFooter(file);
  const inventory = await readInventory(file, offset, footer.start);
  if (inventory.size < 1 || inventory.size > MAX_CHUNKS) fail('Package has no valid encrypted chunks.');
  let total = 0;
  for (const record of inventory.values()) total += record.length;
  if (total + (file.size - footer.start) + offset > MAX_PACKAGE_BYTES) fail('Package exceeds the V13 size limit.');

  const csrf = await apiCsrf();
  const initResponse = await fetch('api-v13.php?action=init', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ package_id: header.package_id, expected_chunks: inventory.size, expected_bytes: total }),
  });
  const init = await initResponse.json();
  if (!initResponse.ok || !init.ok) fail(init.error || 'Unable to initialize upload.');

  const id = init.upload.id;
  const statusResponse = await fetch(`api-v13.php?action=status&id=${encodeURIComponent(id)}`, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-CSRF-Token': csrf } });
  const status = await statusResponse.json();
  if (!statusResponse.ok || !status.ok) fail(status.error || 'Unable to read upload state.');
  const known = new Set(status.chunks || []);
  let sent = 0;
  for (const record of inventory.values()) {
    if (known.has(record.meta.id)) { sent += 1; continue; }
    const cipher = await file.slice(record.offset, record.offset + record.length).arrayBuffer();
    const response = await fetch(`api-v13.php?action=chunk&id=${encodeURIComponent(id)}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf, 'X-Chunk-Id': record.meta.id, 'Content-Type': 'application/octet-stream' },
      body: cipher,
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) fail(payload.error || 'Chunk upload failed.');
    sent += 1;
    $('uploadResult').textContent = `Uploaded ${sent} / ${inventory.size} encrypted chunks.`;
  }

  const finalizeResponse = await fetch(`api-v13.php?action=finalize&id=${encodeURIComponent(id)}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: '{}',
  });
  const finalized = await finalizeResponse.json();
  if (!finalizeResponse.ok || !finalized.ok) fail(finalized.error || 'Upload finalization failed.');
  return finalized;
}

$('upload').onclick = async () => {
  try {
    const file = $('uploadPackage').files[0];
    if (!file) fail('Select a .spk13 package.');
    $('upload').disabled = true;
    $('state').textContent = 'UPLOADING';
    const result = await uploadPackage(file);
    $('uploadResult').textContent = `Encrypted upload finalized: ${result.package_id}`;
    log('V13 resumable ciphertext upload completed. Server received ciphertext chunks only.');
    $('state').textContent = 'READY';
  } catch (error) {
    $('uploadResult').textContent = error.message;
    $('state').textContent = 'ERROR';
    log(error.message);
  } finally { $('upload').disabled = false; }
};

$('state').textContent = 'READY';
$('result').textContent = 'V13 hardened browser vault ready.';
log('V13 initialized. Browser KDF: PBKDF2-HMAC-SHA-256; server-side package engine: Argon2id.');
