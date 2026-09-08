<?php
declare(strict_types=1);

return [
    'storage' => dirname(__DIR__) . '/storage',
    'limits' => [
        'max_upload_bytes' => 1073741824,
        'max_archive_entries' => 100000,
        'max_single_file_bytes' => 536870912,
        'max_total_uncompressed_bytes' => 5368709120,
    ],
];
