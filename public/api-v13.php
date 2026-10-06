<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\JsonResponse;
use SecurePackage\Client\V13Descriptor;
use SecurePackage\Security\RateLimiter;
use SecurePackage\Security\WebSecurity;
use SecurePackage\Storage\AtomicFile;
use SecurePackage\Storage\ChunkStore;
use SecurePackage\Storage\ResumableUploadV13;

WebSecurity::startSession();
WebSecurity::applyHeaders();
$config = require dirname(__DIR__) . '/config/config.php';
$store = new ChunkStore($config['storage']['chunks'], 16 * 1024 * 1024);
$uploads = new ResumableUploadV13($config['storage']['upload_inventory'] . DIRECTORY_SEPARATOR . 'v13', 7200, V13Descriptor::MAX_CHUNKS, V13Descriptor::MAX_PACKAGE_BYTES);
$admission = new RateLimiter($config['storage']['rate_limits'], 20, 900);
$chunkAdmission = new RateLimiter($config['storage']['rate_limits'] . DIRECTORY_SEPARATOR . 'v13-chunks', 1200, 900);

function v13_json(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function v13_owner(): string
{
    return session_id() . '|' . WebSecurity::ownerToken();
}

function v13_body(): array
{
    $length = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
    if ($length > 65536) {
        v13_json(['ok' => false, 'error' => 'Request body is too large.'], 413);
    }
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 65536) {
        v13_json(['ok' => false, 'error' => 'Request body is too large.'], 413);
    }
    $data = json_decode($raw ?: '{}', true, 32);
    if (!is_array($data)) {
        v13_json(['ok' => false, 'error' => 'Invalid JSON request.'], 400);
    }
    return $data;
}

$action = (string) ($_GET['action'] ?? '');
if ($action === 'csrf') {
    v13_json(['ok' => true, 'csrf' => WebSecurity::csrfToken()]);
}

try {
    WebSecurity::assertCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);

    if ($action === 'descriptor') {
        v13_json(['ok' => true, 'descriptor' => V13Descriptor::descriptor()]);
    }

    if ($action === 'init') {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        if (!$admission->allow('v13:init:' . $ip)) {
            v13_json(['ok' => false, 'error' => 'Upload admission limit reached.'], 429);
        }
        $data = v13_body();
        $packageId = (string) ($data['package_id'] ?? '');
        V13Descriptor::validatePackageId($packageId);
        $expectedChunks = filter_var($data['expected_chunks'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => V13Descriptor::MAX_CHUNKS]]);
        $expectedBytes = filter_var($data['expected_bytes'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => V13Descriptor::MAX_PACKAGE_BYTES]]);
        if ($expectedChunks === false || $expectedBytes === false) {
            v13_json(['ok' => false, 'error' => 'Invalid upload declaration.'], 400);
        }
        v13_json(['ok' => true, 'upload' => $uploads->create(v13_owner(), $packageId, $expectedChunks, $expectedBytes)]);
    }

    $id = (string) ($_GET['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
        v13_json(['ok' => false, 'error' => 'Invalid upload identifier.'], 400);
    }

    if ($action === 'status') {
        v13_json(['ok' => true] + $uploads->inventory($id, v13_owner()));
    }

    if ($action === 'chunk') {
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        if (!$chunkAdmission->allow('v13:chunk:' . $ip)) {
            v13_json(['ok' => false, 'error' => 'Upload throughput limit reached.'], 429);
        }
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
        if ($contentLength < 16 || $contentLength > V13Descriptor::CHUNK_MAX + 32) {
            v13_json(['ok' => false, 'error' => 'Encrypted chunk is invalid.'], 413);
        }
        $uploads->state($id, v13_owner());
        $cipher = file_get_contents('php://input');
        if ($cipher === false || strlen($cipher) !== $contentLength) {
            v13_json(['ok' => false, 'error' => 'Invalid request body.'], 400);
        }
        $chunkId = strtolower((string) ($_SERVER['HTTP_X_CHUNK_ID'] ?? ''));
        if ($cipher === false || $cipher === '') {
            v13_json(['ok' => false, 'error' => 'Invalid request body.'], 400);
        }
        $created = false;
        try {
            $created = $store->put($chunkId, $cipher);
            $state = $uploads->addChunk($id, v13_owner(), $chunkId, $cipher);
        } catch (Throwable $error) {
            if (!empty($created)) {
                $store->delete($chunkId);
            }
            throw $error;
        }
        v13_json(['ok' => true, 'state' => $state]);
    }

    if ($action === 'finalize') {
        $state = $uploads->finalize($id, v13_owner());
        $dir = $config['storage']['packages'] . DIRECTORY_SEPARATOR . 'v13';
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to initialize package storage.');
        }
        $meta = [
            'upload_id' => $id,
            'package_id' => $state['package_id'],
            'expected_chunks' => $state['expected_chunks'],
            'expected_bytes' => $state['expected_bytes'],
            'finalized_at' => gmdate('c'),
            'format' => V13Descriptor::FORMAT,
        ];
        AtomicFile::write($dir . DIRECTORY_SEPARATOR . $state['package_id'] . '.json', json_encode($meta, JSON_THROW_ON_ERROR));
        v13_json(['ok' => true, 'package_id' => $state['package_id'], 'state' => $state]);
    }

    if ($action === 'delete-upload') {
        $uploads->delete($id, v13_owner());
        v13_json(['ok' => true]);
    }

    v13_json(['ok' => false, 'error' => 'Unknown action.'], 404);
} catch (Throwable) {
    v13_json(['ok' => false, 'error' => 'Request failed.'], 400);
}
