<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Crypto\V14KeyDerivation;
use SecurePackage\Project\V14Descriptor;
use SecurePackage\Security\CanonicalJson;

$core = [
    'format' => V14Descriptor::FORMAT,
    'version' => 14,
    'schema' => 1,
    'package_id' => str_repeat('a', 48),
    'created_at' => '2026-10-01T00:00:00Z',
    'salt' => base64_encode(random_bytes(32)),
    'crypto' => [
        'kdf' => V14Descriptor::kdfProfile(),
        'aead' => 'xchacha20poly1305-ietf',
        'key_wrap' => 'xchacha20poly1305-ietf',
        'stream' => 'secretstream-xchacha20poly1305',
        'key_separation' => 'HKDF-SHA-256',
        'hash' => 'sha256',
    ],
];
$binding = V14KeyDerivation::headerBinding($core);
if (!hash_equals($binding, hash('sha256', CanonicalJson::encode($core)))) throw new RuntimeException('Header binding is not canonical.');
$core['package_id'] = str_repeat('b', 48);
if (hash_equals($binding, V14KeyDerivation::headerBinding($core))) throw new RuntimeException('Header binding is not sensitive to identity.');

$header = $core;
$header['header_binding'] = V14KeyDerivation::headerBinding($core);
$header['key_slots'] = [
    'primary' => [
        'type' => 'primary',
        'version' => 1,
        'nonce' => base64_encode(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)),
        'wrapped_key' => base64_encode(random_bytes(V14Descriptor::KEY_BYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES)),
    ],
    'recovery' => null,
];
V14Descriptor::assertHeader($header);

$header['unexpected'] = true;
try {
    V14Descriptor::assertHeader($header);
    throw new RuntimeException('Unknown header field was accepted.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Invalid package header.') throw $e;
}

$header = array_diff_key($header, ['unexpected' => true]);
$header['created_at'] = '2026-02-31T99:99:99Z';
try {
    V14Descriptor::assertHeader($header);
    throw new RuntimeException('Invalid timestamp was accepted.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Invalid package timestamp.') throw $e;
}

echo "V14 header binding and strict schema tests passed.\n";
