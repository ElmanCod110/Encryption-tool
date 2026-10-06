<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$checks = [
    'PHP >= 8.2' => version_compare(PHP_VERSION, '8.2.0', '>='),
    'Sodium extension' => extension_loaded('sodium'),
    'Zip extension' => extension_loaded('zip'),
    'Randomness API' => function_exists('random_bytes'),
    'Argon2id support' => defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13'),
];
$failed = false;
foreach ($checks as $name => $ok) {
    echo ($ok ? '[PASS] ' : '[FAIL] ') . $name . PHP_EOL;
    $failed = $failed || !$ok;
}
exit($failed ? 1 : 0);
