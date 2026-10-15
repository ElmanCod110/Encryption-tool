<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$sourceRoot = dirname(__DIR__);
$fixture = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-release-sign-' . bin2hex(random_bytes(8));
if (!mkdir($fixture, 0700, true)) throw new RuntimeException('Unable to create release-signing fixture.');

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    foreach (new DirectoryIterator($path) as $entry) {
        if (!$entry->isDot()) $removeTree($entry->getPathname());
    }
    @rmdir($path);
};

try {
    foreach (['app', 'bin', 'config', 'public'] as $directory) {
        if (!mkdir($fixture . DIRECTORY_SEPARATOR . $directory, 0700, true)) {
            throw new RuntimeException('Unable to prepare release-signing fixture.');
        }
    }
    foreach (['bootstrap.php', 'composer.json', 'composer.lock', 'VERSION'] as $file) {
        if (!copy($sourceRoot . DIRECTORY_SEPARATOR . $file, $fixture . DIRECTORY_SEPARATOR . $file)) {
            throw new RuntimeException('Unable to copy release-signing fixture.');
        }
    }

    $keypair = sodium_crypto_sign_keypair();
    $secretKey = sodium_crypto_sign_secretkey($keypair);
    $publicKey = sodium_crypto_sign_publickey($keypair);
    sodium_memzero($keypair);
    $keyFile = $fixture . DIRECTORY_SEPARATOR . 'test-private-key.hex';
    if (file_put_contents($keyFile, bin2hex($secretKey) . PHP_EOL, LOCK_EX) !== 129) {
        sodium_memzero($secretKey);
        throw new RuntimeException('Unable to write temporary signing key.');
    }
    @chmod($keyFile, 0600);
    sodium_memzero($secretKey);

    $environment = getenv();
    if (!is_array($environment)) $environment = [];
    $environment['SECURE_PACKAGE_TRUSTED_RELEASE_KEY_HEX'] = bin2hex($publicKey);

    $run = static function (array $command, array $env): array {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), $env);
        if (!is_resource($process)) throw new RuntimeException('Unable to start release integrity process.');
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return ['status' => proc_close($process), 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    };

    $signed = $run([PHP_BINARY, $sourceRoot . '/bin/sign-release.php', $keyFile, $fixture], $environment);
    if ($signed['status'] !== 0 || !str_contains($signed['stdout'], 'signed successfully')) {
        throw new RuntimeException('Release signer failed to produce a complete signed manifest.');
    }

    $verified = $run([PHP_BINARY, $sourceRoot . '/bin/verify-release.php', $fixture], $environment);
    if ($verified['status'] !== 0
        || !str_contains($verified['stdout'], 'Release signature: PASS')
        || !str_contains($verified['stdout'], 'Active-source hashes: PASS')) {
        throw new RuntimeException('Release signer output failed external-trust-root verification.');
    }

    echo "Release signer external trust-root test passed.\n";
} finally {
    $removeTree($fixture);
}
