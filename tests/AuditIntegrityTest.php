<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Storage\AuditLogger;

$root = sys_get_temp_dir() . '/secure-package-v5-audit-' . bin2hex(random_bytes(5));
$file = $root . '/events.jsonl';
$logger = new AuditLogger($file);
$logger->event('test.one', ['account_id' => 'a']);
$logger->event('test.two', [
    'token' => 'should-not-persist',
    'password_hash' => 'password-hash-secret',
    'api_token' => 'api-token-secret',
    'session_id' => 'session-secret',
    'recovery_key' => 'recovery-key-secret',
    'private_key' => 'private-key-secret',
    'authorization_header' => 'authorization-secret',
    'csrf_token' => 'csrf-secret',
    'account_id' => 'account-safe',
    'result_count' => 2,
]);
if (!$logger->verify()) throw new RuntimeException('Audit chain should verify.');
$data = file_get_contents($file);
foreach (['should-not-persist', 'password-hash-secret', 'api-token-secret', 'session-secret', 'recovery-key-secret', 'private-key-secret', 'authorization-secret', 'csrf-secret'] as $secret) {
    if (str_contains((string) $data, $secret)) throw new RuntimeException('Sensitive audit context leaked: ' . $secret);
}
foreach (['account-safe', '"result_count":2'] as $safeValue) {
    if (!str_contains((string) $data, $safeValue)) throw new RuntimeException('Safe audit context was unexpectedly removed: ' . $safeValue);
}
$data = str_replace('"result_count":2', '"result_count":3', (string) $data);
file_put_contents($file, $data, LOCK_EX);
if ($logger->verify()) throw new RuntimeException('Tampered audit chain was accepted.');

$missingHeadFile = $root . '/missing-head.jsonl';
$missingHeadLogger = new AuditLogger($missingHeadFile);
$missingHeadLogger->event('before.head.loss', ['account_id' => 'safe']);
if (!unlink($missingHeadFile . '.head')) throw new RuntimeException('Unable to prepare missing-head test.');
$missingHeadRejected = false;
try {
    new AuditLogger($missingHeadFile);
} catch (RuntimeException) {
    $missingHeadRejected = true;
}
if (!$missingHeadRejected) throw new RuntimeException('Missing audit head silently reset a non-empty chain.');

$corruptHeadFile = $root . '/corrupt-head.jsonl';
$corruptHeadLogger = new AuditLogger($corruptHeadFile);
$corruptHeadLogger->event('before.head.corruption', ['account_id' => 'safe']);
if (file_put_contents($corruptHeadFile . '.head', 'not-a-valid-head', LOCK_EX) === false) {
    throw new RuntimeException('Unable to prepare corrupt-head test.');
}
$appendRejected = false;
try {
    $corruptHeadLogger->event('must.not.append', ['account_id' => 'safe']);
} catch (RuntimeException) {
    $appendRejected = true;
}
if (!$appendRejected) throw new RuntimeException('Corrupted audit chain accepted a new event.');
$corruptLines = file($corruptHeadFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($corruptLines) || count($corruptLines) !== 1) {
    throw new RuntimeException('Audit logger appended to a corrupted chain.');
}

echo "Audit integrity tests passed.\n";
