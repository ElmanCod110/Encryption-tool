<?php
declare(strict_types=1);

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "The sodium extension is required.\n");
    exit(1);
}
$keypair = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey($keypair);
$public = sodium_crypto_sign_publickey($keypair);
file_put_contents('php://stdout', bin2hex($public) . PHP_EOL);
fwrite(STDERR, "PRIVATE KEY (store outside the repository):\n" . bin2hex($secret) . PHP_EOL);
