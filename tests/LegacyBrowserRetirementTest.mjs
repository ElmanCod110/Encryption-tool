import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(resolve(root, path), 'utf8');

assert.equal(existsSync(resolve(root, 'public/client/v13/vault-v13.js')), false, 'V13 vault parser must not ship in the active public tree');
assert.equal(existsSync(resolve(root, 'public/client/v13/worker.js')), false, 'V13 worker must not ship in the active public tree');
assert.equal(existsSync(resolve(root, 'public/client/v13/vault-v13.css')), false, 'V13 UI assets must not ship in the active public tree');

const retiredPage = read('public/client-vault.html');
assert.match(retiredPage, /no longer supported/i);
assert.doesNotMatch(retiredPage, /vault-v13\.js|worker\.js/);

for (const path of ['public/api-v13.php', 'public/client-v13.php', 'public/health-v13.php']) {
  const source = read(path);
  assert.match(source, /410/);
  assert.doesNotMatch(source, /V13Descriptor|ResumableUploadV13/);
}
const api = read('public/api.php');
const controller = read('app/Api/PackageController.php');
assert.doesNotMatch(api, /V13Descriptor|ResumableUploadV13|V14PackageReader|V14PackageService/);
assert.doesNotMatch(controller, /V13Descriptor|ResumableUploadV13|V14PackageReader|V14PackageService/);
console.log('Legacy browser retirement checks passed.');
