<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

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
    $expect(410, $request('api-v13.php?action=descriptor'), 'Retired V13 upload API');
    $expect(410, $request('client-v13.php'), 'Retired V13 descriptor endpoint');
    $expect(410, $request('health-v13.php'), 'Retired V13 health endpoint');
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
    $packageId = str_repeat('a', 48);
    $storageRoot = $fixture . DIRECTORY_SEPARATOR . 'storage';
    $catalogDir = $storageRoot . DIRECTORY_SEPARATOR . 'catalog';
    $packagesDir = $storageRoot . DIRECTORY_SEPARATOR . 'packages';
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
        || ($listed['storage_available'] ?? null) !== false
        || ($listed['size_bytes'] ?? null) !== null
        || ($listed['format'] ?? null) !== 'UNSUPPORTED_LEGACY'
        || ($listed['revoked'] ?? null) !== false) {
        throw new RuntimeException('Encrypted package inventory omitted or misreported safe package metadata.');
    }

    $legacyLink = $request(
        'api.php?action=access-token',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['package_id' => $packageId], JSON_THROW_ON_ERROR)
    );
    $expect(404, $legacyLink, 'Legacy package download is retired');

    // Exercise the real hosted SPKG path end to end: source ZIP upload, archive
    // extraction, stable binary creation, authenticated download, restore, and ZIP export.
    if (!class_exists(ZipArchive::class)) throw new RuntimeException('ZIP extension is required for SPKG API integration.');
    $sourceZipPath = $base . DIRECTORY_SEPARATOR . 'source.zip';
    $zip = new ZipArchive();
    if ($zip->open($sourceZipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create SPKG API source ZIP.');
    }
    $zip->addFromString('hello.txt', "SPKG API integration fixture\n");
    $zip->addFromString('nested/readme.txt', "Nested SPKG fixture\n");
    if (!$zip->close()) throw new RuntimeException('Unable to finalize SPKG API source ZIP.');
    $zipBytes = file_get_contents($sourceZipPath);
    if (!is_string($zipBytes) || $zipBytes === '') throw new RuntimeException('SPKG source ZIP is empty.');

    $uploadInit = $request(
        'api.php?action=upload-init',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['total_bytes' => strlen($zipBytes), 'sha256' => hash('sha256', $zipBytes)], JSON_THROW_ON_ERROR)
    );
    $expect(201, $uploadInit, 'Initialize SPKG source upload');
    $uploadInitData = json_decode($uploadInit['body'], true, 16, JSON_THROW_ON_ERROR);
    $uploadId = (string) ($uploadInitData['upload']['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{48}$/', $uploadId)) throw new RuntimeException('SPKG upload ID is invalid.');

    $uploadChunk = $request(
        'api.php?action=upload-chunk',
        'POST',
        [
            'Content-Type: application/octet-stream',
            'Cookie: ' . $cookie,
            'X-CSRF-Token: ' . $csrf,
            'X-Upload-ID: ' . $uploadId,
            'X-Upload-Offset: 0',
            'Content-Length: ' . strlen($zipBytes),
        ],
        $zipBytes
    );
    $expect(200, $uploadChunk, 'Upload SPKG source bytes');

    $uploadComplete = $request(
        'api.php?action=upload-complete',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['upload_id' => $uploadId], JSON_THROW_ON_ERROR)
    );
    $expect(200, $uploadComplete, 'Finalize SPKG source upload');
    $uploadCompleteData = json_decode($uploadComplete['body'], true, 32, JSON_THROW_ON_ERROR);
    $jobId = (string) ($uploadCompleteData['job_id'] ?? '');
    $archiveId = (string) ($uploadCompleteData['state']['pending'][0]['id'] ?? '');
    if ($jobId === '' || !preg_match('/^[a-f0-9]{32}$/', $archiveId)) {
        throw new RuntimeException('SPKG archive job metadata is invalid.');
    }

    $archiveStep = $request(
        'api.php?action=archive-step',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['job_id' => $jobId, 'archive_id' => $archiveId, 'password' => ''], JSON_THROW_ON_ERROR)
    );
    $expect(200, $archiveStep, 'Extract SPKG source archive');
    $archiveStepData = json_decode($archiveStep['body'], true, 32, JSON_THROW_ON_ERROR);
    if (($archiveStepData['state']['status'] ?? null) !== 'ready_to_build') {
        throw new RuntimeException('SPKG source archive did not reach ready_to_build.');
    }

    $packagePassword = 'StableApi!Password2026';
    $packagePattern = 'StableApi#Pattern2026';
    $built = $request(
        'api.php?action=build',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode([
            'job_id' => $jobId,
            'project_name' => 'stable-api-integration-project',
            'password' => $packagePassword,
            'pattern' => $packagePattern,
            'create_recovery' => true,
        ], JSON_THROW_ON_ERROR)
    );
    $expect(201, $built, 'Build stable SPKG package');
    $builtData = json_decode($built['body'], true, 32, JSON_THROW_ON_ERROR);
    $builtPackageId = (string) ($builtData['package_id'] ?? '');
    $downloadPath = (string) ($builtData['download'] ?? '');
    $recoveryKey = (string) ($builtData['recovery_key'] ?? '');
    if (($builtData['format'] ?? null) !== 'SPKG'
        || !preg_match('/^[a-f0-9]{48}$/', $builtPackageId)
        || !str_starts_with($downloadPath, 'download.php?token=')
        || $recoveryKey === '') {
        throw new RuntimeException('SPKG build response violates the active format contract.');
    }

    $downloaded = $request($downloadPath);
    $expect(200, $downloaded, 'Download encrypted SPKG package');
    if (substr($downloaded['body'], 0, 8) !== "\xD3\x82\xA1\x4F\xC7\x5E\x90\x6B"
        || !str_contains(implode("\n", $downloaded['headers']), $builtPackageId . '.spkg')) {
        throw new RuntimeException('Downloaded package is not a binary SPKG artifact.');
    }

    $restored = $request(
        'api.php?action=decrypt',
        'POST',
        array_merge($common, ['X-CSRF-Token: ' . $csrf]),
        json_encode(['package_id' => $builtPackageId, 'password' => $packagePassword, 'pattern' => $packagePattern], JSON_THROW_ON_ERROR)
    );
    $expect(200, $restored, 'Restore SPKG with primary credentials');
    $restoredData = json_decode($restored['body'], true, 32, JSON_THROW_ON_ERROR);
    $restorePath = (string) ($restoredData['restore_download'] ?? '');
    if (!str_starts_with($restorePath, 'download-restored.php?token=')) {
        throw new RuntimeException('SPKG restore response did not provide a restore download.');
    }
    $restoredZipResponse = $request($restorePath);
    $expect(200, $restoredZipResponse, 'Download restored SPKG contents');
    $restoredZipPath = $base . DIRECTORY_SEPARATOR . 'restored.zip';
    if (file_put_contents($restoredZipPath, $restoredZipResponse['body']) !== strlen($restoredZipResponse['body'])) {
        throw new RuntimeException('Unable to save restored SPKG ZIP fixture.');
    }
    $restoredZip = new ZipArchive();
    if ($restoredZip->open($restoredZipPath) !== true) throw new RuntimeException('Restored SPKG output is not a ZIP archive.');
    $hello = $restoredZip->getFromName('hello.txt');
    $nested = $restoredZip->getFromName('nested/readme.txt');
    $restoredZip->close();
    if ($hello !== "SPKG API integration fixture\n" || $nested !== "Nested SPKG fixture\n") {
        throw new RuntimeException('SPKG API round-trip changed the source files.');
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
