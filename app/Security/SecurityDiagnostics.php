<?php
declare(strict_types=1);

namespace SecurePackage\Security;

/**
 * Provides non-secret runtime checks for the current V14 server diagnostics endpoint and CLI.
 */
final class SecurityDiagnostics
{
    public static function run(string $projectRoot): array
    {
        $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        $checks = [
            'php_version' => version_compare(PHP_VERSION, '8.2.0', '>='),
            'sodium' => extension_loaded('sodium'),
            'random' => function_exists('random_bytes'),
            'zip' => extension_loaded('zip'),
            'pdo_mysql' => extension_loaded('pdo_mysql'),
            'https' => $https,
            'csp' => true,
            'public_storage_separation' => !is_dir($projectRoot . '/public/storage'),
            'env_not_in_public' => !is_file($projectRoot . '/public/.env'),
            'private_keys_absent' => self::privateKeyScan($projectRoot),
        ];
        $critical = ['php_version', 'sodium', 'random', 'public_storage_separation', 'env_not_in_public', 'private_keys_absent'];
        $secure = true;
        foreach ($critical as $name) if (($checks[$name] ?? false) !== true) $secure = false;
        return [
            'version' => 14,
            'author' => 'ElmanCod110',
            'checks' => $checks,
            'secure' => $secure,
            'transport_warning' => !$https ? 'HTTPS is not enabled in this environment.' : null,
        ];
    }

    private static function privateKeyScan(string $root): bool
    {
        $bad = 0;
        foreach ([
            '-----BEGIN PRIVATE ' . 'KEY-----',
            '-----BEGIN RSA PRIVATE ' . 'KEY-----',
            '-----BEGIN EC PRIVATE ' . 'KEY-----',
        ] as $needle) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                if (!$file->isFile() || str_contains((string)$file->getPath(), DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR) || $file->getPathname() === $root . '/bin/source-audit.php') {
                    continue;
                }
                if ($file->getSize() > 5 * 1024 * 1024) {
                    continue;
                }
                $contents = @file_get_contents($file->getPathname());
                if ($contents !== false && str_contains($contents, $needle)) {
                    $bad++;
                }
            }
        }
        return $bad === 0;
    }
}
