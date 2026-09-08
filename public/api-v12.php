<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Client\V12Descriptor;
use SecurePackage\Security\WebSecurity;
use SecurePackage\Storage\ChunkStore;
use SecurePackage\Storage\ResumableUploadV12;

WebSecurity::startSession();
WebSecurity::applyHeaders(true);
$config = require dirname(__DIR__) . '/config/config.php';
$store = new ChunkStore($config['storage']['chunks'], 16 * 1024 * 1024);
$uploads = new ResumableUploadV12($config['storage']['upload_inventory'], 7200, 10_000_000, 4 * 1024 * 1024 * 1024);

function v12_json(array $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}
function v12_owner(): string { return session_id() . '|' . WebSecurity::ownerToken(); }
function v12_body(): array { $raw = file_get_contents('php://input'); $data = json_decode($raw ?: '{}', true); return is_array($data) ? $data : []; }
$action = (string)($_GET['action'] ?? '');
if ($action === 'csrf') v12_json(['ok' => true, 'csrf' => WebSecurity::csrfToken()]);
try {
    WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
    if ($action === 'descriptor') v12_json(['ok' => true, 'descriptor' => V12Descriptor::descriptor()]);
    if ($action === 'init') {
        $d = v12_body();
        $packageId = (string)($d['package_id'] ?? '');
        V12Descriptor::validatePackageId($packageId);
        $chunks = (int)($d['expected_chunks'] ?? 0);
        $bytes = (int)($d['expected_bytes'] ?? 0);
        v12_json(['ok' => true, 'upload' => $uploads->create(v12_owner(), $packageId, $chunks, $bytes)]);
    }
    $id = (string)($_GET['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{48}$/', $id)) v12_json(['ok' => false, 'error' => 'Invalid upload identifier.'], 400);
    if ($action === 'status') v12_json(['ok' => true] + $uploads->inventory($id, v12_owner()));
    if ($action === 'chunk') {
        $cipher = file_get_contents('php://input');
        $chunkId = strtolower((string)($_SERVER['HTTP_X_CHUNK_ID'] ?? ''));
        if (!is_string($cipher)) v12_json(['ok' => false, 'error' => 'Invalid request body.'], 400);
        $created = $store->put($chunkId, $cipher);
        try {
            $state = $uploads->addChunk($id, v12_owner(), $chunkId, $cipher);
        } catch (Throwable $error) {
            if ($created) $store->delete($chunkId);
            throw $error;
        }
        v12_json(['ok' => true, 'state' => $state]);
    }
    if ($action === 'finalize') {
        $state = $uploads->finalize($id, v12_owner());
        $dir = $config['storage']['packages'] . '/v12';
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Unable to initialize package storage.');
        $meta = ['upload_id'=>$id,'package_id'=>$state['package_id'],'expected_chunks'=>$state['expected_chunks'],'expected_bytes'=>$state['expected_bytes'],'finalized_at'=>gmdate('c'),'format'=>'SECURE-BROWSER-V12'];
        AtomicFile::write($dir . '/' . $state['package_id'] . '.json', json_encode($meta, JSON_THROW_ON_ERROR));
        v12_json(['ok'=>true,'package_id'=>$state['package_id'],'state'=>$state]);
    }
    if ($action === 'delete-upload') {
        $uploads->delete($id, v12_owner());
        v12_json(['ok'=>true]);
    }
    v12_json(['ok'=>false, 'error'=>'Unknown action.'], 404);
} catch (Throwable $e) {
    v12_json(['ok'=>false, 'error'=>'Request failed.'], 400);
}
