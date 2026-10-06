<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Storage\AuditLogger;

$root = sys_get_temp_dir() . '/secure-package-v5-audit-' . bin2hex(random_bytes(5));
$file = $root . '/events.jsonl';
$logger = new AuditLogger($file);
$logger->event('test.one', ['account_id' => 'a']);
$logger->event('test.two', ['token' => 'should-not-persist', 'value' => 2]);
if (!$logger->verify()) throw new RuntimeException('Audit chain should verify.');
$data = file_get_contents($file);
$data = str_replace('"value":2', '"value":3', (string) $data);
file_put_contents($file, $data, LOCK_EX);
if ($logger->verify()) throw new RuntimeException('Tampered audit chain was accepted.');

echo "Audit integrity tests passed.\n";
