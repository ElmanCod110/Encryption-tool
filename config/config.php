<?php
declare(strict_types=1);

return [
    'app' => ['name'=>'Secure Package','author'=>'ElmanCod110','format'=>'SECURE-BROWSER-V12','version'=>12],
    'storage' => [
        'root'=>dirname(__DIR__).'/storage','packages'=>dirname(__DIR__).'/storage/packages','temp'=>dirname(__DIR__).'/storage/temp','uploads'=>dirname(__DIR__).'/storage/uploads','catalog'=>dirname(__DIR__).'/storage/catalog','accounts'=>dirname(__DIR__).'/storage/accounts','audit'=>dirname(__DIR__).'/storage/audit','rate_limits'=>dirname(__DIR__).'/storage/rate-limits','chunks'=>dirname(__DIR__).'/storage/chunks','upload_inventory'=>dirname(__DIR__).'/storage/upload-inventory'
    ],
    'limits' => [
        'max_upload_bytes'=>1024*1024*1024*1024,'upload_chunk_bytes'=>8*1024*1024,'max_archive_entries'=>100000,'max_single_file_bytes'=>16*1024*1024*1024,'max_total_uncompressed_bytes'=>100*1024*1024*1024,'max_archive_depth'=>8,'max_nested_archives'=>64,'max_manifest_nodes'=>1000000,'max_package_entries'=>1000000,'max_package_size_bytes'=>1024*1024*1024*1024,'job_ttl_seconds'=>7200,'upload_ttl_seconds'=>7200,'restore_ttl_seconds'=>900,'download_token_ttl_seconds'=>900,'max_request_json_bytes'=>2*1024*1024,'max_login_body_bytes'=>64*1024,'max_restore_path_bytes'=>4096,'max_restore_files'=>1000000,'max_restore_total_bytes'=>100*1024*1024*1024
    ],
    'rate_limit'=>['max_failures_per_window'=>12,'window_seconds'=>900],
    'crypto'=>['kdf'=>['ops'=>SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,'mem'=>SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE],'padding_block_bytes'=>1024*1024],
];
