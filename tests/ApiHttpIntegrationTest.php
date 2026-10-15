<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageId;
use SecurePackage\Project\V14PackageBuilder;

$sourceRoot = dirname(__DIR__);
$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-api-http-' . bin2hex(random_bytes(8));
$fixture = $base . DIRECTORY_SEPARATOR . 'fixture';
$sessions = $base . DIRECTORY_SEPARATOR . 'sessions';
if (!mkdir($base, 0700, true) || !mkdir($sessions, 0700, true)) {
    throw new RuntimeException('Unable to create HTTP integration fixture directory.');
}

$copyTree = static function (string $source, string $destination) use (&$copyTree): void {
    if (!is_dir($destination) && !mkdir($destination, 0700, true) && !is_dir($destination)) {
        throw new RuntimeException('Unable to create isolated fixture directory.');
    }
    foreach (new DirectoryIterator($source) as $entry) {
        if ($entry->isDot() || $entry->isLink()) continue;
        $from = $entry->getPathname();
        $to = $destination . DIRECTORY_SEPARATOR . $entry->getFilename();
        if ($entry->isDir()) {
            $copyTree($from, $to);
        } elseif ($entry->isFile() && !copy($from, $to)) {
            throw new RuntimeException('Unable to copy isolated fixture file.');
        }
    }
};

foreach (['app', 'config', 'public'] as $directory) {
    $copyTree($sourceRoot . DIRECTORY_SEPARATOR . $directory, $fixture . DIRECTORY_SEPARATOR . $directory);
}
foreach (['bootstrap.php', 'VERSION'] as $file) {
    if (!copy($sourceRoot . DIRECTORY_SEPARATOR . $file, $fixture . DIRECTORY_SEPARATOR . $file)) {
        throw new RuntimeException('Unable to prepare isolated fixture.');
    }
}

$log = $base . DIRECTORY_SEPARATOR . 'server.log';
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($socket === false) {
    throw new RuntimeException('Unable to reserve an HTTP test port.');
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$port = (int) substr(strrchr((string) $address, ':'), 1);
$url = 'http://127.0.0.1:' . $port . '/';
$descriptors = [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']];
$process = proc_open([PHP_BINARY, '-d', 'session.save_path=' . $sessions, '-S', '127.0.0.1:' . $port, '-t', $fixture . DIRECTORY_SEPARATOR . 'public'], $descriptors, $pipes, $fixture);
if (!is_resource($process)) {
    throw new RuntimeException('Unable to start the PHP HTTP test server.');
}
fclose($pipes[0]);

$request = static function (string $path, string $method = 'GET', array $headers = [], string $body = '') use ($url): array {
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => implode("\r\n", $headers),
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 3,
    ]]);
    $responseBody = @file_get_contents($url . $path, false, $context);
    $responseHeaders = $http_response_header ?? [];
    $status = 0;
    foreach ($responseHeaders as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $header, $match)) {
            $status = (int) $match[1];
            break;
        }
    }
    return ['status' => $status, 'body' => (string) $responseBody, 'headers' => $responseHeaders];
};

$expect = static function (int $status, array $response, string $case): void {
    if ($response['status'] !== $status) {
        throw new RuntimeException($case . ': expected HTTP ' . $status . ', got ' . $response['status'] . '.');
    }
};

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
    $ready = false;
    for ($attempt = 0; $attempt < 40; $attempt++) {
        $response = $request('api.php?action=unknown-action');
        if ($response['status'] !== 0) {
            $ready = true;
            break;
        }
        usleep(100_000);
    }
    if (!$ready) {
        throw new RuntimeException('PHP HTTP test server did not become ready.');
    }

    $expect(404, $request('api.php?action=unknown-action'), 'Unknown action');
    $expect(405, $request('api.php?action=login', 'GET'), 'GET login method');
    $expect(415, $request('api.php?action=login', 'POST', ['Content-Type: text/plain'], '{}'), 'Login media type');

    $indexResponse = $request('');
    $expect(200, $indexResponse, 'Index and session bootstrap');
    if (!preg_match('/<meta name="csrf-token" content="([a-f0-9]{64})">/', $indexResponse['body'], $csrfMatch)) {
        throw new RuntimeException('Index did not render a CSRF token.');
    }
    $csrf = $csrfMatch[1];

    $cookie = '';
    foreach ($indexResponse['headers'] as $header) {
        if (stripos($header, 'Set-Cookie: SECUREPKGSESSID=') === 0
            && preg_match('/SECUREPKGSESSID=([^;]+)/', $header, $cookieMatch)) {
            $cookie = 'SECUREPKGSESSID=' . $cookieMatch[1];
            break;
        }
    }
    if ($cookie === '') throw new RuntimeException('Index did not set the expected session cookie.');

    $common = ['Content-Type: application/json', 'Cookie: ' . $cookie];
    $expect(403, $request('api.php?action=login', 'POST', $common, '{}'), 'Missing CSRF token');
    $expect(403, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf, 'Origin: https://attacker.example']), '{}'), 'Cross-origin request');
    $expect(401, $request('api.php?action=packages', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{}'), 'Unauthenticated package listing');
    $missingJob = $request(
        'api.php?action=archive-step',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['job_id' => 'invalid', 'archive_id' => 'invalid', 'password' => ''], JSON_THROW_ON_ERROR)
    );
    $expect(404, $missingJob, 'Missing archive job');
    $expect(400, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{invalid-json'), 'Malformed JSON');
    $invalidLogin = $request(
        'api.php?action=login',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['username' => 'invalid username', 'password' => 'Cobalt!River72_Moon'], JSON_THROW_ON_ERROR)
    );
    $expect(401, $invalidLogin, 'Malformed username login');

    $registerResponse = $request(
        'api.php?action=register',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['username' => 'test-user', 'password' => 'NeverLogged!Passphrase2026'], JSON_THROW_ON_ERROR)
    );
    $expect(201, $registerResponse, 'Register test account');
    $registration = json_decode($registerResponse['body'], true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($registration) || !is_string($registration['csrf'] ?? null)) {
        throw new RuntimeException('Registration did not return a CSRF token.');
    }
    $csrf = $registration['csrf'];
    $cookie = '';
    foreach ($registerResponse['headers'] as $header) {
        if (stripos($header, 'Set-Cookie: SECUREPKGSESSID=') === 0
            && preg_match('/SECUREPKGSESSID=([^;]+)/', $header, $cookieMatch)) {
            $cookie = 'SECUREPKGSESSID=' . $cookieMatch[1];
        }
    }
    if ($cookie === '') throw new RuntimeException('Registration did not preserve the session cookie.');
    $common = ['Content-Type: application/json', 'Cookie: ' . $cookie];

    $catalogPath = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'catalog';
    $catalogBackup = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'catalog-backup';
    if (!is_dir($catalogPath) || !rename($catalogPath, $catalogBackup)) {
        throw new RuntimeException('Unable to prepare catalog storage failure fixture.');
    }
    try {
        if (file_put_contents($catalogPath, 'not-a-directory') === false) {
            throw new RuntimeException('Unable to prepare catalog storage failure fixture.');
        }
        $catalogFailure = $request(
            'api.php?action=packages',
            'POST',
            array_merge($common, ['X-CSRF-Token: ' . $csrf]),
            '{}'
        );
        $expect(500, $catalogFailure, 'Package catalog initialization failure');
        if (!str_contains($catalogFailure['body'], 'Internal server error.')
            || str_contains($catalogFailure['body'], 'RuntimeException')
            || str_contains($catalogFailure['body'], 'catalog')
            || str_contains($catalogFailure['body'], $fixture)) {
            throw new RuntimeException('Catalog initialization failure exposed implementation details.');
        }
    } finally {
        if (is_file($catalogPath) || is_link($catalogPath)) @unlink($catalogPath);
        if (is_dir($catalogBackup)) @rename($catalogBackup, $catalogPath);
    }

    // Exercise the actual HTTP restore boundary with a valid package and a blocked temp directory.
    $packageId = PackageId::generate();
    $packageSource = $base . DIRECTORY_SEPARATOR . 'restore-source';
    $packageDirectory = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'packages' . DIRECTORY_SEPARATOR . $packageId;
    if (!mkdir($packageSource, 0700, true) || !mkdir($packageDirectory, 0700, true)) {
        throw new RuntimeException('Unable to prepare restore source/package fixture.');
    }
    if (file_put_contents($packageSource . DIRECTORY_SEPARATOR . 'restore-fixture.txt', "restore storage test\\n") === false) {
        throw new RuntimeException('Unable to write restore source fixture.');
    }
    $restorePassword = 'Strong!Password2026#';
    $restorePattern = 'Az!71_xYp#42Qw9';
    try {
        (new V14PackageBuilder())->build($packageSource, $packageDirectory, $restorePassword, $restorePattern, $packageId, true);
    } finally {
        sodium_memzero($restorePassword);
        sodium_memzero($restorePattern);
    }
    (new PackageCatalog($catalogPath))->create($packageId, 'account:' . $registration['account_id'], 'restore-failure-fixture');

    $tempPath = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'temp';
    $tempBackup = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'temp-backup';
    if (!is_dir($tempPath) || !rename($tempPath, $tempBackup)) {
        throw new RuntimeException('Unable to prepare restore destination failure fixture.');
    }
    try {
        if (file_put_contents($tempPath, 'not-a-directory') === false) {
            throw new RuntimeException('Unable to prepare restore destination failure fixture.');
        }
        $restoreFailure = $request(
            'api.php?action=decrypt',
            'POST',
            array_merge($common, ['X-CSRF-Token: ' . $csrf]),
            json_encode([
                'package_id' => $packageId,
                'password' => 'Strong!Password2026#',
                'pattern' => 'Az!71_xYp#42Qw9',
            ], JSON_THROW_ON_ERROR)
        );
        $expect(500, $restoreFailure, 'Restore destination storage failure');
        if (!str_contains($restoreFailure['body'], 'Internal server error.')
            || str_contains($restoreFailure['body'], 'PackageStorageException')
            || str_contains($restoreFailure['body'], 'restore')
            || str_contains($restoreFailure['body'], $fixture)
            || str_contains($restoreFailure['body'], $packageId)) {
            throw new RuntimeException('Restore storage failure exposed implementation details.');
        }
    } finally {
        if (is_file($tempPath) || is_link($tempPath)) @unlink($tempPath);
        if (is_dir($tempBackup)) @rename($tempBackup, $tempPath);
    }

    $accountFile = $fixture . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'accounts' . DIRECTORY_SEPARATOR . 'users.json';
    if (!is_file($accountFile) || file_put_contents($accountFile, '{broken-account-store') === false) {
        throw new RuntimeException('Unable to prepare internal-error response fixture.');
    }
    $internal = $request(
        'api.php?action=login',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['username' => 'test-user', 'password' => 'NeverLogged!Passphrase2026'], JSON_THROW_ON_ERROR)
    );
    $expect(500, $internal, 'Internal storage failure');
    if (!str_contains($internal['body'], 'Internal server error.')
        || str_contains($internal['body'], 'RuntimeException')
        || str_contains($internal['body'], 'users.json')
        || str_contains($internal['body'], $fixture)) {
        throw new RuntimeException('Internal API failure exposed implementation details.');
    }

    echo "API HTTP integration tests passed.\n";
} finally {
    if (is_resource($process)) {
        proc_terminate($process);
        proc_close($process);
    }
    $removeTree($base);
}
