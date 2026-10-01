<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use SecurePackage\Security\CanonicalJson;

final class V14Descriptor
{
    public const FORMAT = 'SECURE-PKG-V14';
    public const VERSION = 14;
    public const SCHEMA = 1;
    public const SALT_BYTES = 32;
    public const KEY_BYTES = 32;
    public const MAX_HEADER_BYTES = 65536;
    public const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;
    public const MAX_NODES = 100000;
    public const MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024;
    public const MAX_TOTAL_PLAIN_BYTES = 100 * 1024 * 1024 * 1024;
    public const MAX_BLOBS = 100000;
    public const MAX_FILENAME_BYTES = 4096;
    public const MAX_DEPTH = 256;

    public static function kdfProfile(): array
    {
        return [
            'name' => 'argon2id13',
            'salt_bytes' => self::SALT_BYTES,
            'ops' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            'mem' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            'key_bytes' => self::KEY_BYTES,
        ];
    }

    public static function core(array $header): array
    {
        return [
            'format' => $header['format'] ?? null,
            'version' => $header['version'] ?? null,
            'schema' => $header['schema'] ?? null,
            'package_id' => $header['package_id'] ?? null,
            'created_at' => $header['created_at'] ?? null,
            'salt' => $header['salt'] ?? null,
            'crypto' => $header['crypto'] ?? null,
        ];
    }

    public static function assertHeader(array $header): void
    {
        $keys = array_keys($header);
        sort($keys);
        $expectedKeys = ['created_at', 'crypto', 'format', 'header_binding', 'key_slots', 'package_id', 'salt', 'schema', 'version'];
        if ($keys !== $expectedKeys) throw new RuntimeException('Invalid package header.');
        if (($header['format'] ?? null) !== self::FORMAT || (int) ($header['version'] ?? 0) !== self::VERSION || (int) ($header['schema'] ?? 0) !== self::SCHEMA) {
            throw new RuntimeException('Unsupported package format.');
        }
        $packageId = (string) ($header['package_id'] ?? '');
        if (!preg_match('/^[a-f0-9]{48}$/', $packageId)) throw new RuntimeException('Invalid package identifier.');
        $createdAt = $header['created_at'] ?? null;
        if (!is_string($createdAt) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $createdAt)) throw new RuntimeException('Invalid package timestamp.');
        $date = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $createdAt, new DateTimeZone('UTC'));
        $errors = DateTimeImmutable::getLastErrors();
        if ($date === false || ($errors !== false && ($errors['warning_count'] !== 0 || $errors['error_count'] !== 0)) || $date->format('Y-m-d\TH:i:s\Z') !== $createdAt) throw new RuntimeException('Invalid package timestamp.');
        $salt = base64_decode((string) ($header['salt'] ?? ''), true);
        if ($salt === false || strlen($salt) !== self::SALT_BYTES) throw new RuntimeException('Invalid package salt.');
        if (!is_array($header['crypto'] ?? null)) throw new RuntimeException('Invalid cryptographic profile.');
        $crypto = $header['crypto'];
        $cryptoKeys = array_keys($crypto); sort($cryptoKeys);
        if ($cryptoKeys !== ['aead', 'hash', 'kdf', 'key_separation', 'key_wrap', 'stream']) throw new RuntimeException('Unsupported cryptographic profile.');
        $kdf = $crypto['kdf'] ?? null;
        if (!is_array($kdf)) throw new RuntimeException('Unsupported cryptographic profile.');
        $kdfKeys = array_keys($kdf); sort($kdfKeys); $expectedKdfKeys = ['key_bytes', 'mem', 'name', 'ops', 'salt_bytes'];
        if ($kdfKeys !== $expectedKdfKeys || CanonicalJson::encode($kdf) !== CanonicalJson::encode(self::kdfProfile()) || ($crypto['aead'] ?? null) !== 'xchacha20poly1305-ietf' || ($crypto['stream'] ?? null) !== 'secretstream-xchacha20poly1305' || ($crypto['key_wrap'] ?? null) !== 'xchacha20poly1305-ietf' || ($crypto['hash'] ?? null) !== 'sha256' || ($crypto['key_separation'] ?? null) !== 'HKDF-SHA-256') {
            throw new RuntimeException('Unsupported cryptographic profile.');
        }
        $binding = (string) ($header['header_binding'] ?? '');
        if (!preg_match('/^[a-f0-9]{64}$/', $binding)) throw new RuntimeException('Invalid header binding.');
        if (!is_array($header['key_slots'] ?? null)) throw new RuntimeException('Missing key slots.');
        $slotKeys = array_keys($header['key_slots']); sort($slotKeys);
        if ($slotKeys !== ['primary', 'recovery'] || !is_array($header['key_slots']['primary'])) throw new RuntimeException('Missing primary key slot.');
        self::assertSlot($header['key_slots']['primary'], 'primary');
        if ($header['key_slots']['recovery'] !== null) self::assertSlot($header['key_slots']['recovery'], 'recovery');
        $expected = hash('sha256', CanonicalJson::encode(self::core($header)));
        if (!hash_equals($binding, $expected)) throw new RuntimeException('Package header integrity check failed.');
    }

    public static function assertSlot(array $slot, string $kind): void
    {
        $keys = array_keys($slot); sort($keys);
        if ($keys !== ['nonce', 'type', 'version', 'wrapped_key'] || ($slot['type'] ?? null) !== $kind || (int) ($slot['version'] ?? 0) !== 1) throw new RuntimeException('Invalid key slot.');
        $nonce = base64_decode((string) ($slot['nonce'] ?? ''), true);
        $wrapped = base64_decode((string) ($slot['wrapped_key'] ?? ''), true);
        if ($nonce === false || strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES || $wrapped === false || strlen($wrapped) !== self::KEY_BYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            throw new RuntimeException('Invalid key slot.');
        }
    }
}
