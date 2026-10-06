<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\UnifiedBrowserPackage;
if (UnifiedBrowserPackage::FORMAT !== 'SECURE-BROWSER-V7') throw new RuntimeException('Format mismatch.');
if (UnifiedBrowserPackage::MAGIC !== 'SPK7BIN1') throw new RuntimeException('Magic mismatch.');
if (UnifiedBrowserPackage::CHUNK_SIZE !== 4194304) throw new RuntimeException('Chunk size mismatch.');
UnifiedBrowserPackage::validatePackageId(str_repeat('a',48));
try { UnifiedBrowserPackage::validatePackageId('invalid'); throw new RuntimeException('Invalid identifier accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Invalid package identifier.') throw $e; }
$d=UnifiedBrowserPackage::descriptor();
foreach(['format','version','kdf_iterations','key_separation','content_encryption','integrity','server_plaintext'] as $k) if(!array_key_exists($k,$d)) throw new RuntimeException('Descriptor field missing.');
echo "V7 format tests passed.\n";
