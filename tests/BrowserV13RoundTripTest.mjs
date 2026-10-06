import fs from 'node:fs/promises';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

const root = new URL('../public/client/v13/', import.meta.url);
const clientCode = await fs.readFile(new URL('vault-v13.js', root), 'utf8');
const workerCode = await fs.readFile(new URL('worker.js', root), 'utf8');

const elements = new Map();
function makeElement(id) {
  return {
    id,
    textContent: '', value: '', disabled: false, files: [], style: { width: '' },
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    focus() {}, click() {},
    onclick: null, onchange: null, ondrop: null, ondragover: null, ondragleave: null,
  };
}
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  },
  createElement() { return makeElement('generated'); },
};

const indexedDB = {
  open() {
    const db = {
      createObjectStore() {},
      transaction() {
        const tx = {
          objectStore() { return { put() {}, delete() {} }; },
          oncomplete: null,
          onerror: null,
        };
        setTimeout(() => tx.oncomplete?.(), 0);
        return tx;
      },
    };
    const request = { result: db, onupgradeneeded: null, onsuccess: null, onerror: null };
    setTimeout(() => { request.onupgradeneeded?.(); request.onsuccess?.(); }, 0);
    return request;
  },
};

class DirectWorker {
  constructor() {
    this.onmessage = null;
    this.onerror = null;
    const self = { postMessage: (data) => setTimeout(() => this.onmessage?.({ data }), 0) };
    const scope = {
      self, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView,
      Date, Map, Set, Number, String, Boolean, Math, JSON, Promise, Error, TypeError,
      parseInt,
      btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
      atob: (value) => Buffer.from(value, 'base64').toString('binary'),
    };
    vm.runInNewContext(workerCode, scope, { filename: 'worker.js' });
    this.handler = scope.self.onmessage;
  }
  postMessage(message) {
    try {
      Promise.resolve(this.handler({ data: message })).catch((error) => this.onerror?.(error));
    } catch (error) {
      this.onerror?.(error);
    }
  }
}

class OutFile {
  constructor(name) { this.name = name; this.parts = []; }
  async createWritable() {
    return {
      write: (data) => this.parts.push(Buffer.from(data)),
      close: () => {},
    };
  }
  bytes() { return Buffer.concat(this.parts); }
}
class OutDir {
  constructor() { this.dirs = new Map(); this.files = new Map(); }
  async getDirectoryHandle(name, { create = false } = {}) {
    if (/\.dll$/i.test(name) && create) {
      throw new TypeError("Failed to execute 'getDirectoryHandle' on 'FileSystemDirectoryHandle': Name is not allowed.");
    }
    if (this.dirs.has(name)) return this.dirs.get(name);
    if (this.files.has(name)) throw new DOMException('Directory expected', 'TypeMismatchError');
    if (!create) { const error = new DOMException('Not found', 'NotFoundError'); throw error; }
    const dir = new OutDir(); this.dirs.set(name, dir); return dir;
  }
  async getFileHandle(name, { create = false } = {}) {
    if (/\.dll$/i.test(name) && create) {
      throw new TypeError("Failed to execute 'getFileHandle' on 'FileSystemDirectoryHandle': Name is not allowed.");
    }
    if (this.dirs.has(name)) throw new DOMException('File expected', 'TypeMismatchError');
    if (this.files.has(name)) return this.files.get(name);
    if (!create) { const error = new DOMException('Not found', 'NotFoundError'); throw error; }
    const file = new OutFile(name); this.files.set(name, file); return file;
  }
  async removeEntry(name, { recursive = false } = {}) {
    if (this.files.delete(name)) return;
    if (recursive && this.dirs.delete(name)) return;
    if (this.dirs.delete(name)) return;
    throw new DOMException('Not found', 'NotFoundError');
  }
}

const sandbox = {
  console,
  document,
  window: { showSaveFilePicker: undefined },
  showDirectoryPicker: null,
  Worker: DirectWorker,
  File, Blob, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView,
  Date, Map, Set, Number, String, Boolean, Math, JSON, Promise, Error, TypeError,
  crypto: webcrypto, indexedDB,
  URL: { createObjectURL: () => '', revokeObjectURL() {} },
  btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  DOMException,
  setTimeout, clearTimeout,
};
vm.createContext(sandbox);
vm.runInContext(clientCode, sandbox, { filename: 'vault-v13.js' });

// Cross-platform names are path-safe at package level and adapted only when the local filesystem rejects them.
for (const name of ['CON.txt', 'version.dll', 'foo:bar.txt', 'trail.']) {
  const parts = sandbox.safeParts(name);
  if (parts.length !== 1) throw new Error(`Path parsing regression for ${name}.`);
}

const password = 'Strong!Password2026';
const pattern = 'Zx7!Pattern_2046';
const files = [
  new File(['hello world'], 'hello.txt', { type: 'text/plain' }),
  new File([new Uint8Array([0, 1, 2, 3, 254, 255])], 'data.bin', { type: 'application/octet-stream' }),
  new File(['executable payload'], 'version.dll', { type: 'application/octet-stream' }),
];
const outputA = new OutDir();
sandbox.showDirectoryPicker = async () => outputA;
sandbox.window.showDirectoryPicker = sandbox.showDirectoryPicker;

const built = await sandbox.build(files, password, pattern, true);
if (!(built.blob instanceof Blob) || !built.recoveryKey) throw new Error('Browser V13 build output is invalid.');
const primary = await sandbox.restore(built.blob, password, pattern, '', outputA);
if (primary.count !== 3 || primary.adaptedCount < 1) throw new Error('Primary restore or compatibility mapping failed.');
if (outputA.files.get('hello.txt').bytes().toString() !== 'hello world') throw new Error('Primary restore content mismatch.');
if (!outputA.files.get('data.bin').bytes().equals(Buffer.from([0, 1, 2, 3, 254, 255]))) throw new Error('Binary restore content mismatch.');
const blockedAlias = [...outputA.files.keys()].find((name) => /\.v13-restore$|^_V13_[0-9a-f]+\.bin$/i.test(name));
if (!blockedAlias || outputA.files.get(blockedAlias).bytes().toString() !== 'executable payload') throw new Error('Browser-blocked extension was not restored safely.');

const outputB = new OutDir();
sandbox.showDirectoryPicker = async () => outputB;
sandbox.window.showDirectoryPicker = sandbox.showDirectoryPicker;
const recovery = await sandbox.restore(built.blob, '', '', built.recoveryKey, outputB);
if (recovery.count !== 3) throw new Error('Recovery restore failed.');

let wrongPasswordRejected = false;
try {
  await sandbox.restore(built.blob, 'Wrong!Password2026', pattern, '', new OutDir());
} catch (_) {
  wrongPasswordRejected = true;
}
if (!wrongPasswordRejected) throw new Error('Wrong password was accepted.');

const outputC = new OutDir();
outputC.files.set('hello.txt', new OutFile('hello.txt'));
const collision = await sandbox.restore(built.blob, password, pattern, '', outputC);
if (collision.count !== 3) throw new Error('Collision-safe restore failed.');
if (!outputC.files.has('hello.txt') || outputC.files.get('hello.txt').bytes().length !== 0) throw new Error('Existing target was overwritten.');
if (![...outputC.files.keys()].some((name) => /^hello \(1\)\.txt$/i.test(name))) throw new Error('Collision-safe filename was not created.');

const packageInput = sandbox.document.getElementById('package');
packageInput.files = [built.blob];
const abortError = new DOMException('User cancelled', 'AbortError');
sandbox.showDirectoryPicker = async () => { throw abortError; };
sandbox.window.showDirectoryPicker = sandbox.showDirectoryPicker;
await sandbox.document.getElementById('decrypt').onclick();
if (sandbox.document.getElementById('state').textContent !== 'READY') throw new Error('Directory picker cancellation was not handled cleanly.');
if (!/Restore cancelled/.test(sandbox.document.getElementById('decryptResult').textContent)) throw new Error('Cancellation result message regression.');

console.log('Browser V13 round-trip tests passed.');
