<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\V13Descriptor;

$d = V13Descriptor::descriptor();
if ($d['format'] !== V13Descriptor::FORMAT || $d['version'] !== 13) throw new RuntimeException('V13 identity failed.');
if ($d['kdf'] !== 'PBKDF2-HMAC-SHA-256' || $d['kdf_iterations'] !== 1_500_000) throw new RuntimeException('V13 KDF profile failed.');
if ($d['server_plaintext'] !== false || $d['restore_policy'] !== 'fail-on-existing-path') throw new RuntimeException('V13 privacy/restore policy failed.');
if ($d['limits']['max_header_bytes'] !== 2 * 1024 * 1024 || $d['limits']['max_manifest_bytes'] !== 32 * 1024 * 1024) throw new RuntimeException('V13 parser limits failed.');
try { V13Descriptor::validatePackageId(str_repeat('a', 47)); throw new RuntimeException('Invalid package id was accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Invalid package identifier.') throw $e; }
V13Descriptor::validatePackageId(str_repeat('a', 48));
echo "V13 descriptor tests passed.\n";
