<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageNotAvailableException;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-package-catalog-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) {
    throw new RuntimeException('Unable to create package catalog test directory.');
}

$packageId = str_repeat('a', 48);
$owner = 'account:owner-a';
try {
    $catalog = new PackageCatalog($directory);
    $catalog->create($packageId, $owner, 'Research package');

    $duplicateRejected = false;
    try {
        $catalog->create($packageId, 'account:owner-b', 'Replacement');
    } catch (RuntimeException) {
        $duplicateRejected = true;
    }
    if (!$duplicateRejected || !hash_equals(hash('sha256', $owner), $catalog->get($packageId)['owner_hash'])) {
        throw new RuntimeException('Duplicate package creation overwrote the existing owner record.');
    }

    $catalog->setExpiry($packageId, $owner, time() + 3600);
    $catalog->revoke($packageId, $owner);
    $record = $catalog->get($packageId);
    if (($record['revoked_at'] ?? null) === null || (int) ($record['expires_at'] ?? 0) <= time()) {
        throw new RuntimeException('Package catalog mutation lost expiry or revocation state.');
    }

    $wrongOwnerRejected = false;
    try {
        $catalog->setExpiry($packageId, 'account:owner-b', null);
    } catch (PackageNotAvailableException) {
        $wrongOwnerRejected = true;
    }
    if (!$wrongOwnerRejected || $catalog->get($packageId)['expires_at'] === null) {
        throw new RuntimeException('Unauthorized catalog mutation was accepted.');
    }

    $unavailableRejected = false;
    try {
        $catalog->assertAvailable($packageId);
    } catch (PackageNotAvailableException) {
        $unavailableRejected = true;
    }
    if (!$unavailableRejected) {
        throw new RuntimeException('Revoked package remained available.');
    }

    $missingPackageTyped = false;
    try {
        $catalog->get(str_repeat('z', 48));
    } catch (PackageNotAvailableException) {
        $missingPackageTyped = true;
    }
    if (!$missingPackageTyped) {
        throw new RuntimeException('Invalid package identifiers were not classified as unavailable.');
    }

    $corruptId = str_repeat('c', 48);
    if (file_put_contents($directory . DIRECTORY_SEPARATOR . $corruptId . '.json', '{invalid-json') === false) {
        throw new RuntimeException('Unable to prepare corrupt catalog fixture.');
    }
    $corruptionRemainedInternal = false;
    try {
        $catalog->get($corruptId);
    } catch (PackageNotAvailableException) {
        throw new RuntimeException('Corrupt catalog data was incorrectly classified as a missing package.');
    } catch (Throwable) {
        $corruptionRemainedInternal = true;
    }
    if (!$corruptionRemainedInternal) {
        throw new RuntimeException('Corrupt catalog data did not produce an internal failure.');
    }

    // Race multiple independent PHP processes against the same new package ID.
    // Exactly one create must win; all other processes must observe the existing record.
    $raceId = str_repeat('b', 48);
    $workerCode = 'require $argv[1]; $catalog = new \\SecurePackage\\Project\\PackageCatalog($argv[2]); try { $catalog->create($argv[3], $argv[4], "Concurrent package"); exit(0); } catch (\\RuntimeException $e) { if (str_contains($e->getMessage(), "already exists")) exit(10); fwrite(STDERR, get_class($e) . ": " . $e->getMessage()); exit(1); }';
    $processes = [];
    for ($i = 0; $i < 8; $i++) {
        $ownerId = 'race-owner-' . $i;
        $pipes = [];
        $process = proc_open(
            [PHP_BINARY, '-r', $workerCode, dirname(__DIR__) . '/bootstrap.php', $directory, $raceId, $ownerId],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start package catalog concurrency worker.');
        }
        fclose($pipes[0]);
        $processes[] = ['process' => $process, 'stdout' => $pipes[1], 'stderr' => $pipes[2]];
    }
    $successes = 0;
    $duplicates = 0;
    foreach ($processes as $worker) {
        $stdout = stream_get_contents($worker['stdout']);
        $stderr = stream_get_contents($worker['stderr']);
        fclose($worker['stdout']);
        fclose($worker['stderr']);
        $exitCode = proc_close($worker['process']);
        if ($exitCode === 0) {
            $successes++;
        } elseif ($exitCode === 10) {
            $duplicates++;
        } else {
            throw new RuntimeException('Catalog concurrency worker failed: ' . trim($stderr . ' ' . $stdout));
        }
    }
    if ($successes !== 1 || $duplicates !== 7) {
        throw new RuntimeException('Concurrent catalog creation did not serialize exactly one winner.');
    }
    $raceRecord = $catalog->get($raceId);
    $ownerMatched = false;
    for ($i = 0; $i < 8; $i++) {
        if (hash_equals((string) $raceRecord['owner_hash'], hash('sha256', 'race-owner-' . $i))) {
            $ownerMatched = true;
            break;
        }
    }
    if (!$ownerMatched) {
        throw new RuntimeException('Concurrent catalog record owner hash is inconsistent.');
    }

    echo "Package catalog mutation regression tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }
    @rmdir($directory);
}
