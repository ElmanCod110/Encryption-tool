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

    // Configuration loading must fail inside the JSON error boundary without leaking details.
    $configFile = $fixture . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php';
    $configOriginal = file_get_contents($configFile);
    if (!is_string($configOriginal)) {
        throw new RuntimeException('Unable to read isolated config fixture.');
    }
    try {
        $configSentinel = 'CONFIG_PRIVATE_SENTINEL_' . bin2hex(random_bytes(8));
        $brokenConfig = "<?php\ndeclare(strict_types=1);\nthrow new RuntimeException('" . $configSentinel . "');\n";
        if (file_put_contents($configFile, $brokenConfig) === false) {
            throw new RuntimeException('Unable to prepare configuration failure fixture.');
        }
        $configFailure = $request('api.php?action=unknown-action');
        $expect(500, $configFailure, 'Configuration initialization failure');
        if (!str_contains($configFailure['body'], 'Internal server error.')
            || str_contains($configFailure['body'], $configSentinel)
            || str_contains($configFailure['body'], 'RuntimeException')
            || str_contains($configFailure['body'], $fixture)) {
            throw new RuntimeException('Configuration failure exposed implementation details.');
        }
    } finally {
        if (file_put_contents($configFile, $configOriginal) === false) {
            throw new RuntimeException('Unable to restore isolated config fixture.');
        }
    }

    $methodRejected = $request('api.php?action=login', 'GET');
    $expect(405, $methodRejected, 'GET login method');
    if (!in_array('Allow: POST', $methodRejected['headers'], true)) {
        throw new RuntimeException('Method rejection did not advertise POST.');
    }
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
    $unauthenticatedPackages = $request('api.php?action=packages', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{}');
    $expect(401, $unauthenticatedPackages, 'Unauthenticated package listing');
    $expect(403, $request('api.php?action=login', 'POST', $common, '{}'), 'Missing CSRF token');
    $expect(403, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf, 'Origin: https://attacker.example']), '{}'), 'Cross-origin request');
    $expect(400, $request('api.php?action=login', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{invalid-json'), 'Malformed JSON');
    $invalidLogin = $request(
        'api.php?action=login',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['username' => 'invalid username', 'password' => 'Cobalt!River72_Moon'], JSON_THROW_ON_ERROR)
    );
    $expect(401, $invalidLogin, 'Malformed username login');

    // Exercise the authenticated encrypted-package inventory without creating real user data.
    $registered = $request(
        'api.php?action=register',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['username' => 'inventory-test-user', 'password' => 'BlueRiver!Inventory2026'], JSON_THROW_ON_ERROR)
    );
    $expect(201, $registered, 'Register inventory test account');
    $registeredData = json_decode($registered['body'], true, 16, JSON_THROW_ON_ERROR);
    if (!is_string($registeredData['account_id'] ?? null) || !is_string($registeredData['csrf'] ?? null)) {
        throw new RuntimeException('Registration did not return account and CSRF metadata.');
    }
    foreach ($registered['headers'] as $header) {
        if (stripos($header, 'Set-Cookie: SECUREPKGSESSID=') === 0
            && preg_match('/SECUREPKGSESSID=([^;]+)/', $header, $cookieMatch)) {
            $cookie = 'SECUREPKGSESSID=' . $cookieMatch[1];
        }
    }
    $csrf = $registeredData['csrf'];
    $common = ['Content-Type: application/json', 'Cookie: ' . $cookie];

    // A malformed or missing job must not be reported as a generic server failure.
    $missingJob = $request(
        'api.php?action=archive-step',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['job_id' => 'invalid', 'archive_id' => 'invalid', 'password' => ''], JSON_THROW_ON_ERROR)
    );
    $expect(404, $missingJob, 'Missing archive job');

    $missingPackage = $request(
        'api.php?action=access-token',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['package_id' => str_repeat('f', 48)], JSON_THROW_ON_ERROR)
    );
    $expect(404, $missingPackage, 'Missing package access token');

    $storageRoot = $fixture . DIRECTORY_SEPARATOR . 'storage';
    $catalogDir = $storageRoot . DIRECTORY_SEPARATOR . 'catalog';
    $packagesDir = $storageRoot . DIRECTORY_SEPARATOR . 'packages';

    // A catalog initialization failure is a storage fault, not a missing-package 404.
    $catalogBackup = $storageRoot . DIRECTORY_SEPARATOR . 'catalog-backup';
    if (!is_dir($catalogDir) || !rename($catalogDir, $catalogBackup)) {
        throw new RuntimeException('Unable to prepare catalog initialization failure fixture.');
    }
    try {
        if (file_put_contents($catalogDir, 'not-a-directory') === false) {
            throw new RuntimeException('Unable to prepare catalog initialization failure fixture.');
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
        if (is_file($catalogDir) || is_link($catalogDir)) @unlink($catalogDir);
        if (is_dir($catalogBackup) && !@rename($catalogBackup, $catalogDir)) {
            throw new RuntimeException('Unable to restore catalog directory after fault injection.');
        }
    }

    $packageId = str_repeat('a', 48);
    if (!is_dir($catalogDir) && !mkdir($catalogDir, 0700, true) && !is_dir($catalogDir)) {
        throw new RuntimeException('Unable to prepare inventory catalog fixture.');
    }
    if (!is_dir($packagesDir) && !mkdir($packagesDir, 0700, true) && !is_dir($packagesDir)) {
        throw new RuntimeException('Unable to prepare inventory package fixture.');
    }
    $encryptedFixture = "test-only-encrypted-package";
    if (file_put_contents($packagesDir . DIRECTORY_SEPARATOR . $packageId . '.spkg14', $encryptedFixture) === false) {
        throw new RuntimeException('Unable to prepare encrypted package fixture.');
    }
    $catalogRecord = [
        'package_id' => $packageId,
        'owner_hash' => hash('sha256', 'account:' . $registeredData['account_id']),
        'name_hash' => hash('sha256', 'inventory-test-package'),
        'created_at' => time(),
        'expires_at' => null,
        'revoked_at' => null,
    ];
    if (file_put_contents($catalogDir . DIRECTORY_SEPARATOR . $packageId . '.json', json_encode($catalogRecord, JSON_THROW_ON_ERROR)) === false) {
        throw new RuntimeException('Unable to prepare inventory catalog record.');
    }
    $inventory = $request('api.php?action=packages', 'POST', array_merge($common, ['X-CSRF-Token: ' . $csrf]), '{}');
    $expect(200, $inventory, 'Authenticated encrypted package inventory');
    $inventoryData = json_decode($inventory['body'], true, 16, JSON_THROW_ON_ERROR);
    $listed = $inventoryData['packages'][0] ?? null;
    if (!is_array($listed)
        || ($listed['package_id'] ?? null) !== $packageId
        || ($listed['storage_available'] ?? null) !== true
        || ($listed['size_bytes'] ?? null) !== strlen($encryptedFixture)
        || ($listed['revoked'] ?? null) !== false) {
        throw new RuntimeException('Encrypted package inventory omitted or misreported safe package metadata.');
    }

    // Use a real encrypted package to reach the restore directory creation path.
    $restorePackageId = PackageId::generate();
    $restoreSource = $base . DIRECTORY_SEPARATOR . 'restore-source';
    $restorePackageDir = $packagesDir . DIRECTORY_SEPARATOR . $restorePackageId;
    if (!mkdir($restoreSource, 0700, true)
        || file_put_contents($restoreSource . DIRECTORY_SEPARATOR . 'restore-fixture.txt', "restore storage test\n") === false) {
        throw new RuntimeException('Unable to prepare restore source fixture.');
    }
    $restorePassword = 'Strong!Password2026#';
    $restorePattern = 'Az!71_xYp#42Qw9';
    try {
        (new V14PackageBuilder())->build($restoreSource, $restorePackageDir, $restorePassword, $restorePattern, $restorePackageId, true);
    } finally {
        sodium_memzero($restorePassword);
        sodium_memzero($restorePattern);
    }
    (new PackageCatalog($catalogDir))->create(
        $restorePackageId,
        'account:' . $registeredData['account_id'],
        'restore-failure-fixture'
    );

    // Keep job/token subdirectories intact, but make only the temporary root unwritable.
    // This lets API service construction succeed and exercises the actual restore-output write.
    $tempPath = $storageRoot . DIRECTORY_SEPARATOR . 'temp';
    $tempMode = is_dir($tempPath) ? (fileperms($tempPath) & 0777) : false;
    $blockedRestoreTest = is_int($tempMode) && @chmod($tempPath, 0500);
    clearstatcache(true, $tempPath);
    if ($blockedRestoreTest && !is_writable($tempPath)) {
        try {
            $restoreFailure = $request(
                'api.php?action=decrypt',
                'POST',
                array_merge($common, ['X-CSRF-Token: ' . $csrf]),
                json_encode([
                    'package_id' => $restorePackageId,
                    'password' => 'Strong!Password2026#',
                    'pattern' => 'Az!71_xYp#42Qw9',
                ], JSON_THROW_ON_ERROR)
            );
            $expect(500, $restoreFailure, 'Restore destination storage failure');
            if (!str_contains($restoreFailure['body'], 'Internal server error.')
                || str_contains($restoreFailure['body'], 'PackageStorageException')
                || str_contains($restoreFailure['body'], 'restore')
                || str_contains($restoreFailure['body'], $fixture)
                || str_contains($restoreFailure['body'], $restorePackageId)) {
                throw new RuntimeException('Restore storage failure exposed implementation details.');
            }
        } finally {
            if (!@chmod($tempPath, $tempMode)) {
                throw new RuntimeException('Unable to restore temporary storage permissions.');
            }
        }
    } else {
        if (is_int($tempMode)) @chmod($tempPath, $tempMode);
        echo "Restore destination permission-failure scenario skipped (host does not enforce directory mode changes).\n";
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
