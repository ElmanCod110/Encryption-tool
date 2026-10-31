<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

$root = dirname(__DIR__);
$fixture = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spkg-local-cli-' . bin2hex(random_bytes(8));
$source = $fixture . DIRECTORY_SEPARATOR . 'source';
$package = $fixture . DIRECTORY_SEPARATOR . 'local-cli.spkg';
$output = $fixture . DIRECTORY_SEPARATOR . 'restored';
if (!mkdir($source, 0700, true)) throw new RuntimeException('Unable to create local CLI test fixture.');
if (file_put_contents($source . DIRECTORY_SEPARATOR . 'local.txt', "Local SPKG CLI round-trip\n") === false) {
    throw new RuntimeException('Unable to write local CLI source fixture.');
}
$password = 'LocalCli!Password2026';
$createOut = '';
$restoreOut = '';
$pattern = 'LocalCli#Pattern2026';

$run = static function (array $command) use ($root): array {
    $pipes = [];
    $process = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes, $root, null);
    if (!is_resource($process)) throw new RuntimeException('Unable to start local SPKG CLI process.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);
    return [$status, (string) $stdout, (string) $stderr];
};

$removeTree = static function (string $path) use (&$removeTree): void {
    if (is_link($path) || is_file($path)) { @unlink($path); return; }
    if (!is_dir($path)) return;
    foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) $removeTree($entry->getPathname());
    @rmdir($path);
};

try {
    $oldPassword = getenv('SPK_PASSWORD');
    $oldPattern = getenv('SPK_PATTERN');
    putenv('SPK_PASSWORD=' . $password);
    putenv('SPK_PATTERN=' . $pattern);
    [$createStatus, $createOut, $createErr] = $run([PHP_BINARY, $root . '/bin/create-package.php', $source, $package]);
    if ($createStatus !== 0 || !is_file($package) || !str_contains($createOut, 'SPKG package created successfully')) {
        throw new RuntimeException('Local SPKG creation failed: ' . $createErr . $createOut);
    }
    $bytes = file_get_contents($package);
    if (!is_string($bytes) || substr($bytes, 0, 8) !== "\xD3\x82\xA1\x4F\xC7\x5E\x90\x6B") {
        throw new RuntimeException('Local CLI did not create the canonical SPKG binary.');
    }
    [$restoreStatus, $restoreOut, $restoreErr] = $run(
        [PHP_BINARY, $root . '/bin/decrypt-package.php', $package, $output],
    );
    if ($restoreStatus !== 0 || !str_contains($restoreOut, 'SPKG package restored successfully')) {
        throw new RuntimeException('Local SPKG restore failed: ' . $restoreErr . $restoreOut);
    }
    $restoredBytes = file_get_contents($output . DIRECTORY_SEPARATOR . 'local.txt');
    if ($restoredBytes !== "Local SPKG CLI round-trip\n") {
        throw new RuntimeException('Local SPKG CLI round-trip changed the plaintext file.');
    }
    echo "Standalone local SPKG CLI round-trip passed without a web server.\n";
} finally {
    if ($password !== '') sodium_memzero($password);
    if ($pattern !== '') sodium_memzero($pattern);
    if ($createOut !== '') sodium_memzero($createOut);
    if ($restoreOut !== '') sodium_memzero($restoreOut);
    if ($oldPassword === false) putenv('SPK_PASSWORD'); else putenv('SPK_PASSWORD=' . $oldPassword);
    if ($oldPattern === false) putenv('SPK_PATTERN'); else putenv('SPK_PATTERN=' . $oldPattern);
    $removeTree($fixture);
}
