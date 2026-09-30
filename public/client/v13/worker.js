'use strict';

const sessions = new Map();
const te = new TextEncoder();
const MAX_SECRET_BYTES = 4096;
const SALT_BYTES = 32;
const ROOT_BYTES = 32;
const IV_BYTES = 12;
const KDF_ITERATIONS = 1_500_000;

const bytes = (value) => value instanceof Uint8Array ? value : new Uint8Array(value);
const text = (value) => typeof value === 'string' ? te.encode(value) : bytes(value);
const concat = (...parts) => {
  const size = parts.reduce((sum, part) => sum + bytes(part).length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    const value = bytes(part);
    output.set(value, offset);
    offset += value.length;
  }
  return output;
};
const hex = (value) => [...bytes(value)].map((x) => x.toString(16).padStart(2, '0')).join('');
const random = (length) => crypto.getRandomValues(new Uint8Array(length));

function assertSecret(value) {
  if (typeof value !== 'string' || value.length === 0 || new TextEncoder().encode(value).length > MAX_SECRET_BYTES) {
    throw new Error('Invalid credential material.');
  }
}

function assertKdf(iterations) {
  if (!Number.isSafeInteger(iterations) || iterations !== KDF_ITERATIONS) {
    throw new Error('Unsupported KDF parameters.');
  }
}

function assertBytes(value, length) {
  if (bytes(value).length !== length) {
    throw new Error('Invalid cryptographic material.');
  }
}

async function digest(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(value)));
}

async function pbkdf(secret, salt, iterations) {
  assertSecret(secret);
  assertBytes(salt, SALT_BYTES);
  assertKdf(iterations);
  const key = await crypto.subtle.importKey('raw', text(secret), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256));
}

async function hkdf(ikm, salt, info, length = 32) {
  const key = await crypto.subtle.importKey('raw', bytes(ikm), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: bytes(salt), info: text(info) }, key, length * 8));
}

async function credentialKey(password, pattern, salt, iterations) {
  const ps = await digest(concat(text('SecurePackage|V13|PBKDF2|password|'), salt));
  const qs = await digest(concat(text('SecurePackage|V13|PBKDF2|pattern|'), salt));
  const passwordKey = await pbkdf(password, ps, iterations);
  const patternKey = await pbkdf(pattern, qs, iterations);
  try {
    return hkdf(concat(passwordKey, patternKey), salt, 'SecurePackage|V13|credential-wrap');
  } finally {
    passwordKey.fill(0);
    patternKey.fill(0);
  }
}

async function recoveryKey(recovery, salt, iterations) {
  assertSecret(recovery);
  const rs = await digest(concat(text('SecurePackage|V13|PBKDF2|recovery|'), salt));
  return pbkdf(recovery, rs, iterations);
}

async function aes(raw, usage = ['encrypt', 'decrypt']) {
  assertBytes(raw, 32);
  return crypto.subtle.importKey('raw', bytes(raw), { name: 'AES-GCM' }, false, usage);
}

function b64(value) {
  const array = bytes(value);
  let output = '';
  for (let offset = 0; offset < array.length; offset += 0x8000) {
    output += String.fromCharCode(...array.subarray(offset, offset + 0x8000));
  }
  return btoa(output);
}

function unb64(value, expectedLength = null) {
  if (typeof value !== 'string' || value.length > 16_000_000) throw new Error('Invalid encoded value.');
  const raw = atob(value);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) output[i] = raw.charCodeAt(i);
  if (expectedLength !== null && output.length !== expectedLength) throw new Error('Invalid encoded value.');
  return output;
}

async function wrap(root, key, aad) {
  assertBytes(root, ROOT_BYTES);
  assertBytes(key, 32);
  const iv = random(IV_BYTES);
  const cryptoKey = await aes(key);
  const value = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: text(aad) }, cryptoKey, root));
  return { iv: b64(iv), value: b64(value) };
}

async function unwrap(slot, key, aad) {
  if (!slot || typeof slot !== 'object') throw new Error('Missing key slot.');
  const iv = unb64(slot.iv, IV_BYTES);
  const value = unb64(slot.value);
  if (value.length !== ROOT_BYTES + 16) throw new Error('Invalid key slot.');
  const cryptoKey = await aes(key);
  const root = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: text(aad) }, cryptoKey, value));
  assertBytes(root, ROOT_BYTES);
  return root;
}

async function nonce(root, context) {
  assertBytes(root, ROOT_BYTES);
  if (typeof context !== 'string' || context.length < 1 || context.length > 512) throw new Error('Invalid nonce context.');
  const nonceKey = await hkdf(root, new Uint8Array(32), 'SecurePackage|V13|nonce-domain');
  const cryptoKey = await crypto.subtle.importKey('raw', nonceKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  nonceKey.fill(0);
  return new Uint8Array((await crypto.subtle.sign('HMAC', cryptoKey, text(context))).slice(0, IV_BYTES));
}

async function crypt(session, purpose, context, iv, data, aad, mode) {
  const raw = await hkdf(session.root, new Uint8Array(32), `SecurePackage|V13|key|${purpose}|${context}`);
  try {
    const cryptoKey = await aes(raw);
    const output = mode === 'enc'
      ? await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: text(aad) }, cryptoKey, bytes(data))
      : await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: text(aad) }, cryptoKey, bytes(data));
    return new Uint8Array(output);
  } finally {
    raw.fill(0);
  }
}

function session(sessionId) {
  if (typeof sessionId !== 'string' || !/^[a-f0-9]{32}$/.test(sessionId)) throw new Error('Session expired.');
  const value = sessions.get(sessionId);
  if (!value || value.expires < Date.now()) {
    if (value) {
      value.root.fill(0);
      value.wrapRaw.fill(0);
      sessions.delete(sessionId);
    }
    throw new Error('Session expired.');
  }
  value.expires = Date.now() + 10 * 60 * 1000;
  return value;
}

self.onmessage = async (event) => {
  const { id, op } = event.data || {};
  try {
    if (!Number.isSafeInteger(id)) throw new Error();

    if (op === 'createSession') {
      assertKdf(event.data.iterations);
      const salt = bytes(event.data.salt);
      const root = bytes(event.data.root);
      assertBytes(salt, SALT_BYTES);
      assertBytes(root, ROOT_BYTES);
      const wrapRaw = await credentialKey(event.data.password, event.data.pattern, salt, event.data.iterations);
      const sessionId = hex(random(16));
      sessions.set(sessionId, { root: new Uint8Array(root), wrapRaw, salt: new Uint8Array(salt), expires: Date.now() + 600_000 });
      self.postMessage({ id, ok: true, result: { sessionId } });
      return;
    }

    if (op === 'unlock') {
      assertKdf(event.data.iterations);
      const salt = bytes(event.data.salt);
      assertBytes(salt, SALT_BYTES);
      const wrapRaw = await credentialKey(event.data.password, event.data.pattern, salt, event.data.iterations);
      try {
        const root = await unwrap(event.data.slot, wrapRaw, `SecurePackage|V13|slot|primary|${event.data.packageId}`);
        const sessionId = hex(random(16));
        sessions.set(sessionId, { root, wrapRaw, salt: new Uint8Array(salt), expires: Date.now() + 600_000 });
        self.postMessage({ id, ok: true, result: { sessionId } });
      } catch (error) {
        wrapRaw.fill(0);
        throw error;
      }
      return;
    }

    if (op === 'unlockRecovery') {
      assertKdf(event.data.iterations);
      const salt = bytes(event.data.salt);
      assertBytes(salt, SALT_BYTES);
      const wrapRaw = await recoveryKey(event.data.recovery, salt, event.data.iterations);
      try {
        const root = await unwrap(event.data.slot, wrapRaw, `SecurePackage|V13|slot|recovery|${event.data.packageId}`);
        const sessionId = hex(random(16));
        sessions.set(sessionId, { root, wrapRaw, salt: new Uint8Array(salt), expires: Date.now() + 600_000 });
        self.postMessage({ id, ok: true, result: { sessionId } });
      } catch (error) {
        wrapRaw.fill(0);
        throw error;
      }
      return;
    }

    if (op === 'wrapCredential') {
      const salt = bytes(event.data.salt);
      const root = bytes(event.data.root);
      assertBytes(salt, SALT_BYTES);
      assertBytes(root, ROOT_BYTES);
      assertKdf(event.data.iterations);
      const wrapRaw = await credentialKey(event.data.password, event.data.pattern, salt, event.data.iterations);
      try {
        const slot = await wrap(root, wrapRaw, `SecurePackage|V13|slot|primary|${event.data.packageId}`);
        self.postMessage({ id, ok: true, result: slot });
      } finally {
        wrapRaw.fill(0);
      }
      return;
    }

    if (op === 'wrapRecovery') {
      const salt = bytes(event.data.salt);
      const root = bytes(event.data.root);
      assertBytes(salt, SALT_BYTES);
      assertBytes(root, ROOT_BYTES);
      assertKdf(event.data.iterations);
      const wrapRaw = await recoveryKey(event.data.recovery, salt, event.data.iterations);
      try {
        const slot = await wrap(root, wrapRaw, `SecurePackage|V13|slot|recovery|${event.data.packageId}`);
        self.postMessage({ id, ok: true, result: slot });
      } finally {
        wrapRaw.fill(0);
      }
      return;
    }

    if (op === 'nonce') {
      const value = await nonce(session(event.data.sessionId).root, event.data.context);
      self.postMessage({ id, ok: true, result: value }, [value.buffer]);
      return;
    }

    if (op === 'crypt') {
      const value = await crypt(session(event.data.sessionId), event.data.purpose, event.data.context, bytes(event.data.iv), event.data.data, event.data.aad, event.data.mode);
      self.postMessage({ id, ok: true, result: value }, [value.buffer]);
      return;
    }

    if (op === 'hash') {
      const value = await digest(event.data.data);
      self.postMessage({ id, ok: true, result: value }, [value.buffer]);
      return;
    }

    if (op === 'destroy') {
      if (typeof event.data.sessionId === 'string') {
        const value = sessions.get(event.data.sessionId);
        if (value) {
          value.root.fill(0);
          value.wrapRaw.fill(0);
          sessions.delete(event.data.sessionId);
        }
      }
      self.postMessage({ id, ok: true, result: true });
      return;
    }

    throw new Error();
  } catch (_) {
    self.postMessage({ id, ok: false, error: 'Client cryptographic operation failed.' });
  }
};
