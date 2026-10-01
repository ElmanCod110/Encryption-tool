<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\V14Aead;
$key = random_bytes(32);
$cipher = V14Aead::seal('test payload', $key, 'aad');
$last = strlen($cipher) - 1;
$cipher[$last] = chr(ord($cipher[$last]) ^ 1);
try { V14Aead::open($cipher, $key, 'aad'); throw new RuntimeException('Tampered V14 ciphertext was accepted.'); } catch (RuntimeException $e) { if ($e->getMessage() === 'Tampered V14 ciphertext was accepted.') throw $e; }
sodium_memzero($key);
echo "V14 tamper detection passed.\n";
