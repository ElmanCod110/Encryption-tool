<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$required = [
    'PHP >= 8.2' => version_compare(PHP_VERSION, '8.2.0', '>='),
    '64-bit PHP runtime' => PHP_INT_SIZE === 8,
    'Sodium extension' => extension_loaded('sodium'),
    'Randomness API' => function_exists('random_bytes'),
    'Argon2id support' => defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13'),
    'XChaCha20-Poly1305-IETF' => function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt') && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt'),
    'Secretstream support' => function_exists('sodium_crypto_secretstream_xchacha20poly1305_init_push') && function_exists('sodium_crypto_secretstream_xchacha20poly1305_init_pull'),
    'HKDF-SHA-256 support' => function_exists('hash_hkdf'),
    'Zip extension' => extension_loaded('zip'),
];
$optional = [];
$failed = false;
foreach ($required as $name => $ok) {
    echo ($ok ? '[PASS] ' : '[FAIL] ') . $name . PHP_EOL;
    $failed = $failed || !$ok;
}
foreach ($optional as $name => $ok) {
    echo ($ok ? '[PASS] ' : '[FAIL] ') . $name . PHP_EOL;
    $failed = $failed || !$ok;
}
exit($failed ? 1 : 0);
