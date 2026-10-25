<?php
declare(strict_types=1);

namespace SecurePackage\Project;

use RuntimeException;

/** Shared, domain-separated cryptographic operations for the stable format. */
final class StablePackageCrypto
{
    public static function deriveCredentialKey(string $password, string $pattern, string $salt, string $packageId, int $ops, int $memoryBytes): string
    {
        StablePackageDescriptor::assertRuntime();
        StablePackageDescriptor::assertKdfParameters($ops, $memoryBytes);
        if (strlen($salt) !== StablePackageDescriptor::SALT_BYTES
            || strlen($packageId) !== StablePackageDescriptor::PACKAGE_ID_BYTES) {
            throw new RuntimeException('Invalid credential derivation context.');
        }
        $passwordSalt = substr(hash('sha256', "SPKG/PWHASH/PASSWORD\0" . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $patternSalt = substr(hash('sha256', "SPKG/PWHASH/PATTERN\0" . $salt, true), 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $passwordKey = sodium_crypto_pwhash(StablePackageDescriptor::KEY_BYTES, $password, $passwordSalt, $ops, $memoryBytes, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $patternKey = null;
        try {
            $patternKey = sodium_crypto_pwhash(StablePackageDescriptor::KEY_BYTES, $pattern, $patternSalt, $ops, $memoryBytes, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
            $combined = $passwordKey . $patternKey;
            try {
                return hash_hkdf('sha256', $combined, StablePackageDescriptor::KEY_BYTES,
                    "SPKG/CREDENTIAL-WRAP\0" . $packageId, $salt);
            } finally {
                sodium_memzero($combined);
            }
        } finally {
            sodium_memzero($passwordKey);
            if (is_string($patternKey)) sodium_memzero($patternKey);
        }
    }

    public static function deriveSubkey(string $root, string $purpose, string $packageId, string $context = ''): string
    {
        if (strlen($root) !== StablePackageDescriptor::KEY_BYTES
            || strlen($packageId) !== StablePackageDescriptor::PACKAGE_ID_BYTES
            || $purpose === '' || strlen($context) > 1024) {
            throw new RuntimeException('Invalid key derivation request.');
        }
        return hash_hkdf('sha256', $root, StablePackageDescriptor::KEY_BYTES,
            "SPKG/" . $purpose . "\0" . $context, $packageId);
    }

    public static function chunkAad(string $coreHash, string $packageId, string $fileId, int $sequence, int $size): string
    {
        if (strlen($coreHash) !== 32 || strlen($packageId) !== StablePackageDescriptor::PACKAGE_ID_BYTES
            || strlen($fileId) !== StablePackageDescriptor::FILE_ID_BYTES || $sequence < 0 || $size < 0) {
            throw new RuntimeException('Invalid authenticated chunk context.');
        }
        return "SPKG/CHUNK\0" . $coreHash . $packageId . $fileId . pack('N', $sequence)
            . StablePackageDescriptor::packUint64($size);
    }

    public static function manifestAad(string $coreHash): string
    {
        if (strlen($coreHash) !== 32) {
            throw new RuntimeException('Invalid authenticated manifest context.');
        }
        return "SPKG/MANIFEST\0" . $coreHash;
    }

    public static function encodeRecoveryKey(string $raw): string
    {
        if (strlen($raw) !== StablePackageDescriptor::KEY_BYTES || StablePackageDescriptor::isZeroBytes($raw)) {
            throw new RuntimeException('Invalid recovery key.');
        }
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function decodeRecoveryKey(string $encoded): string
    {
        if ($encoded === '' || strlen($encoded) > 128 || !preg_match('/^[A-Za-z0-9_-]+$/D', $encoded)) {
            throw new RuntimeException('Unable to open package.');
        }
        $padded = strtr($encoded, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);
        $raw = base64_decode($padded, true);
        if (!is_string($raw) || strlen($raw) !== StablePackageDescriptor::KEY_BYTES
            || StablePackageDescriptor::isZeroBytes($raw)
            || !hash_equals(self::encodeRecoveryKey($raw), $encoded)) {
            throw new RuntimeException('Unable to open package.');
        }
        return $raw;
    }

    public static function unwrapRootKey(array $header, string $password, string $pattern, ?string $recoveryKey): string
    {
        $credentialKey = null;
        $recoveryRaw = null;
        $rootKey = null;
        $macKey = null;
        try {
            if ($recoveryKey !== null && $recoveryKey !== '') {
                if (!$header['has_recovery']) {
                    throw new RuntimeException('Unable to open package.');
                }
                $recoveryRaw = self::decodeRecoveryKey($recoveryKey);
                $rootKey = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $header['recovery_cipher'],
                    "SPKG/KEYWRAP/RECOVERY\0" . $header['core'],
                    $header['recovery_nonce'],
                    $recoveryRaw
                );
            } else {
                \SecurePackage\Security\Validator::validatePassword($password);
                \SecurePackage\Security\Validator::validatePattern($pattern);
                $credentialKey = self::deriveCredentialKey($password, $pattern, $header['salt'],
                    $header['package_id'], $header['ops'], $header['memory_bytes']);
                $rootKey = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $header['primary_cipher'],
                    "SPKG/KEYWRAP/PRIMARY\0" . $header['core'],
                    $header['primary_nonce'],
                    $credentialKey
                );
            }
            if (!is_string($rootKey) || strlen($rootKey) !== StablePackageDescriptor::KEY_BYTES
                || StablePackageDescriptor::isZeroBytes($rootKey)) {
                throw new RuntimeException('Unable to open package.');
            }
            $macKey = self::deriveSubkey($rootKey, 'HEADER-MAC', $header['package_id']);
            $expected = hash_hmac('sha256', substr($header['raw'], 0, StablePackageDescriptor::HEADER_WITHOUT_MAC_BYTES), $macKey, true);
            if (!hash_equals($expected, $header['header_mac'])) {
                sodium_memzero($rootKey);
                $rootKey = null;
                throw new RuntimeException('Unable to open package.');
            }
            return $rootKey;
        } catch (\Throwable $e) {
            if (is_string($rootKey)) sodium_memzero($rootKey);
            // Collapse credential/authentication failures to the same external message.
            throw new RuntimeException('Unable to open package.', 0, $e);
        } finally {
            if (is_string($credentialKey)) sodium_memzero($credentialKey);
            if (is_string($recoveryRaw)) sodium_memzero($recoveryRaw);
            if (is_string($macKey)) sodium_memzero($macKey);
            $password = '';
            $pattern = '';
        }
    }
}