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

echo "Audit integrity tests passed.\n";
