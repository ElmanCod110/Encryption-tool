<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\CryptoEngine;
if (!extension_loaded('sodium')) { fwrite(STDERR, "Sodium is required.\n"); exit(1); }
$key=random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
$payload=random_bytes(16*1024*1024);
$start=microtime(true);
for($i=0;$i<8;$i++){ $cipher=sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($payload,'bench',random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),$key); }
$elapsed=microtime(true)-$start;
$mb=(strlen($payload)*8)/(1024*1024);
echo 'AEAD throughput: '.number_format($mb/$elapsed,2).' MiB/s'.PHP_EOL;
sodium_memzero($key);
echo 'Benchmark completed.'.PHP_EOL;
