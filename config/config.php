<?php
declare(strict_types=1);

return [
    'app' => [
        'name' => 'TCH Secure Package',
        'format' => 'TCH-PKG-V2',
    ],
    'storage' => [
        'root' => dirname(__DIR__) . '/storage',
        'packages' => dirname(__DIR__) . '/storage/packages',
        'temp' => dirname(__DIR__) . '/storage/temp',
        'uploads' => dirname(__DIR__) . '/storage/uploads',
    ],
    'limits' => [
        'max_upload_bytes' => 1073741824,
        'max_archive_entries' => 100000,
        'max_single_file_bytes' => 536870912,
        'max_total_uncompressed_bytes' => 5368709120,
        'max_archive_depth' => 8,
        'max_nested_archives' => 64,
        'max_manifest_nodes' => 100000,
    ],
    'rate_limit' => [
        'max_failures_per_window' => 12,
        'window_seconds' => 900,
    ],
];
