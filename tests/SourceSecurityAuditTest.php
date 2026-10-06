<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';

$root = dirname(__DIR__);
$forbiddenBranding = ['/\bTCH\b/i', '/TC_Hub/i', '/TeamCode Hub/i', '/tch-/i'];
$dangerous = ['/\beval\s*\(/', '/\bcreate_function\s*\(/', '/(?<![:A-Za-z0-9_])passthru\s*\(/', '/(?<![:A-Za-z0-9_])shell_exec\s*\(/', '/(?<![:A-Za-z0-9_])system\s*\(/', '/(?<![:A-Za-z0-9_])proc_open\s*\(/', '/(?<![:A-Za-z0-9_])popen\s*\(/'];
$allowedDangerous = ['tests/SourceSecurityAuditTest.php'];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $file) {
    if (!$file->isFile()) continue;
    $path = str_replace('\\', '/', $file->getPathname());
    if (str_contains($path, '/vendor/')) continue;
    if (str_contains($path, '/archive/legacy/')) continue;
    if ($path === __FILE__) continue;
    if (str_contains($path, '/tests/')) continue;
    if (str_ends_with($path, '/bin/source-audit.php')) continue;
    if (!preg_match('/\.(php|js|html|css|json|md|yml|yaml|xml|env\.example)$/i', $path)) continue;
    $contents = @file_get_contents($path);
    if ($contents === false) continue;
    foreach ($forbiddenBranding as $needle) {
        if (preg_match($needle, $contents)) throw new RuntimeException('Forbidden legacy branding found in ' . $path);
    }
    foreach ($dangerous as $needle) {
        if (preg_match($needle, $contents) && !in_array(str_replace($root . '/', '', $path), $allowedDangerous, true)) {
            throw new RuntimeException('Potentially dangerous call found: ' . $needle . ' in ' . $path);
        }
    }
    foreach ([
        '-----BEGIN PRIVATE ' . 'KEY-----',
        '-----BEGIN RSA PRIVATE ' . 'KEY-----',
        '-----BEGIN EC PRIVATE ' . 'KEY-----',
    ] as $marker) {
        if (str_contains($contents, $marker)) throw new RuntimeException('Private key material found in source: ' . $path);
    }
}
echo "Source security audit passed.\n";
