<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\RateLimiter;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spk-rate-limit-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) throw new RuntimeException('Unable to create limiter test directory.');

try {
    $limiter = new RateLimiter($directory, 2, 900);
    if (!$limiter->allow('login-test') || !$limiter->allow('login-test') || $limiter->allow('login-test')) {
        throw new RuntimeException('Rate limiter did not enforce its configured attempt limit.');
    }
    $limiter->success('login-test');
    if (!$limiter->allow('login-test')) {
        throw new RuntimeException('Successful authentication did not reset the attempt window.');
    }

    $corruptKey = 'corrupt-test';
    $corruptFile = $directory . DIRECTORY_SEPARATOR . hash('sha256', $corruptKey) . '.json';
    file_put_contents($corruptFile, '{invalid-json');
    chmod($corruptFile, 0600);
    if ($limiter->allow($corruptKey)) {
        throw new RuntimeException('Rate limiter failed open on corrupted state.');
    }
    if ($limiter->allow($corruptKey)) {
        throw new RuntimeException('Corrupted limiter state was not kept blocked.');
    }

    echo "Rate limiter regression tests passed.\n";
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_link($file) || is_file($file)) @unlink($file);
    }
    @rmdir($directory);
}
