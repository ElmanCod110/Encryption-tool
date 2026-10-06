<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\V12BuildState;

if (!extension_loaded('sodium') || !function_exists('openssl_encrypt')) {
    echo "V12 build-state test skipped: crypto extensions unavailable.\n";
    exit(0);
}
$salt = random_bytes(32);
$password = 'Aa9!VeryStrongPassword2026';
$pattern = 'pAtTeRn#9Xy_42!q';
$state = ['package_id' => bin2hex(random_bytes(24)), 'files_completed' => 12, 'records' => 44, 'updated_at' => time()];
$sealed = V12BuildState::seal($state, $password, $pattern, $salt);
$opened = V12BuildState::open($sealed, $password, $pattern, $salt);
if ($opened !== $state) throw new RuntimeException('Build state round-trip failed.');
try {
    V12BuildState::open($sealed, $password . 'x', $pattern, $salt);
    throw new RuntimeException('Wrong password accepted.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Unable to authenticate build state.') throw $e;
}
try {
    V12BuildState::seal($state + ['password' => 'forbidden'], $password, $pattern, $salt);
    throw new RuntimeException('Sensitive build state accepted.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Sensitive data is not permitted in build state.') throw $e;
}
echo "V12 build-state tests passed.\n";
