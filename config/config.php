<?php
declare(strict_types=1);

return [
    'app' => [
        'name' => 'Secure Package',
        'author' => 'ElmanCod110',
        'format' => 'SECURE-PKG-V3',
        'version' => 3,
    ],
    'storage' => [
        'root' => dirname(__DIR__) . '/storage',
        'packages' => dirname(__DIR__) . '/storage/packages',
        'temp' => dirname(__DIR__) . '/storage/temp',
        'uploads' => dirname(__DIR__) . '/storage/uploads',
        'rate_limits' => dirname(__DIR__) . '/storage/rate-limits',
    ],
    'limits' => [
        'max_upload_bytes' => 1073741824,
        'max_archive_entries' => 100000,
        'max_single_file_bytes' => 536870912,
        'max_total_uncompressed_bytes' => 5368709120,
        'max_archive_depth' => 8,
        'max_nested_archives' => 64,
        'max_manifest_nodes' => 100000,
        'max_package_entries' => 2048,
        'max_package_size_bytes' => 8589934592,
        'job_ttl_seconds' => 3600,
        'restore_ttl_seconds' => 900,
    ],
    'rate_limit' => [
        'max_failures_per_window' => 12,
        'window_seconds' => 900,
    ],
    'crypto' => [
        'kdf' => [
            'ops' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            'mem' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        ],
        'padding_block_bytes' => 1048576,
    ],
];
