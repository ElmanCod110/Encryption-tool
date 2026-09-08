<?php
declare(strict_types=1);
namespace SecurePackage\Client;
final class V11Descriptor
{
    public const FORMAT='SECURE-BROWSER-V11'; public const VERSION=11; public const MAGIC='SPK11BIN1';
    public const MIN_CHUNK=1024*1024; public const TARGET_CHUNK=4*1024*1024; public const MAX_CHUNK=8*1024*1024;
    public static function descriptor(): array { return ['format'=>self::FORMAT,'version'=>self::VERSION,'container'=>self::MAGIC,'kdf'=>'PBKDF2-HMAC-SHA-256','kdf_iterations'=>1200000,'key_derivation'=>'HKDF-SHA-256','encryption'=>'AES-256-GCM','chunking'=>'content-defined-streaming','merkle'=>'SHA-256-incremental','local_plaintext_upload'=>false,'large_file_mode'=>true,'durable_checkpoint'=>true,'resumable_upload'=>true,'content_addressed_chunks'=>true]; }
    public static function validPackageId(string $id): bool { return preg_match('/^[a-f0-9]{48}$/',$id)===1; }
}
