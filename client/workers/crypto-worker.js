/* Browser-side cryptographic worker for the local vault profile. */
const encoder = new TextEncoder();
const sessions = new Map();
const SESSION_TTL_MS = 10 * 60 * 1000;

function toBytes(value) { return typeof value === 'string' ? encoder.encode(value) : new Uint8Array(value); }
function hex(bytes) { return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function touch(session) { session.expires = Date.now() + SESSION_TTL_MS; return session; }
function cleanup() { const now = Date.now(); for (const [id, session] of sessions) if (session.expires <= now) sessions.delete(id); }

async function deriveSession(password, pattern, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', toBytes(password + '\u0000' + pattern), 'PBKDF2', false, ['deriveBits']);
  const masterBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256);
  const master = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey']);
  const manifestKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: toBytes('SecurePackage|V6|manifest') }, master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const nameKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: toBytes('SecurePackage|V6|filename') }, master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const fileKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: toBytes('SecurePackage|V6|file') }, master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { manifestKey, nameKey, fileKey };
}

function getKey(session, purpose) {
  if (purpose === 'manifest') return session.manifestKey;
  if (purpose === 'name') return session.nameKey;
  if (purpose === 'file') return session.fileKey;
  throw new Error('Unsupported key purpose.');
}

self.onmessage = async (event) => {
  const { id, op } = event.data || {};
  cleanup();
  try {
    if (op === 'start') {
      const salt = new Uint8Array(event.data.salt);
      const keys = await deriveSession(event.data.password, event.data.pattern, salt, event.data.iterations);
      const sessionId = hex(crypto.getRandomValues(new Uint8Array(16)));
      sessions.set(sessionId, touch(keys));
      self.postMessage({ id, ok: true, result: { sessionId } });
      return;
    }
    if (op === 'destroy') {
      sessions.delete(event.data.sessionId);
      self.postMessage({ id, ok: true, result: true });
      return;
    }
    const session = sessions.get(event.data.sessionId);
    if (!session) throw new Error('Browser crypto session expired.');
    touch(session);
    const key = getKey(session, event.data.purpose);
    const iv = new Uint8Array(event.data.iv);
    const aad = toBytes(event.data.aad || '');
    if (op === 'encrypt') {
      const result = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, new Uint8Array(event.data.plaintext));
      self.postMessage({ id, ok: true, result }, [result]);
      return;
    }
    if (op === 'decrypt') {
      const result = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, new Uint8Array(event.data.ciphertext));
      self.postMessage({ id, ok: true, result }, [result]);
      return;
    }
    throw new Error('Unsupported crypto operation.');
  } catch (_) {
    self.postMessage({ id, ok: false, error: 'Client cryptographic operation failed.' });
  }
};
