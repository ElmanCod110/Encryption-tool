#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
$config = require dirname(__DIR__) . '/config/config.php';
$maxAge = (int) ($config['limits']['job_ttl_seconds'] ?? 3600);
$roots = [
    $config['storage']['temp'],
    $config['storage']['rate_limits'],
];
$now = time();
$removed = 0;
foreach ($roots as $root) {
    if (!is_dir($root)) continue;
    $iterator = new FilesystemIterator($root, FilesystemIterator::SKIP_DOTS);
    foreach ($iterator as $item) {
        if ($item->getFilename() === '.gitkeep') continue;
        if ($item->getMTime() > $now - $maxAge) continue;
        if ($item->isDir()) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($item->getPathname(), FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $child) $child->isDir() ? @rmdir($child->getPathname()) : @unlink($child->getPathname());
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
        $removed++;
    }
}
echo "Removed {$removed} stale storage entries.\n";
