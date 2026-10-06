<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Storage\ResumableUploadV13;

$root = sys_get_temp_dir() . '/sp-v13-upload-' . bin2hex(random_bytes(5));
$store = new ResumableUploadV13($root, 7200, 4, 1024 * 1024);
$owner = 'session-owner-test';
$packageId = str_repeat('b', 48);
$cipher = random_bytes(32);
$chunkId = hash('sha256', $cipher);
$state = $store->create($owner, $packageId, 1, strlen($cipher));
if ($state['format'] !== 'SECURE-BROWSER-V13') throw new RuntimeException('Upload format mismatch.');
try { $store->state($state['id'], 'wrong-owner'); throw new RuntimeException('Cross-owner state access accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Upload does not exist.') throw $e; }
$after = $store->addChunk($state['id'], $owner, $chunkId, $cipher);
if ($after['received_chunks'] !== 1 || $after['received_bytes'] !== strlen($cipher)) throw new RuntimeException('Chunk accounting failed.');
$again = $store->addChunk($state['id'], $owner, $chunkId, $cipher);
if ($again['received_chunks'] !== 1) throw new RuntimeException('Duplicate chunk accounting failed.');
$final = $store->finalize($state['id'], $owner);
if ($final['finalized'] !== true) throw new RuntimeException('Finalize failed.');
try { $store->addChunk($state['id'], $owner, $chunkId, $cipher); throw new RuntimeException('Finalized upload accepted a chunk.'); } catch (RuntimeException $e) { if ($e->getMessage() !== 'Upload already finalized.') throw $e; }
$store->delete($state['id'], $owner);
@rmdir($root);
echo "V13 upload tests passed.\n";
