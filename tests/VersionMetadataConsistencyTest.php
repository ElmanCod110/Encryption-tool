<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$version = trim((string) file_get_contents($root . '/VERSION'));
$changelog = (string) file_get_contents($root . '/CHANGELOG.md');
$policy = (string) file_get_contents($root . '/VERSIONING.md');

if (!preg_match('/^\d+\.\d+\.\d+$/', $version)) {
    throw new RuntimeException('VERSION must contain one semantic version.');
}
if (!preg_match('/^## ' . preg_quote($version, '/') . ' — /m', $changelog)) {
    throw new RuntimeException('The current application version must have a matching changelog heading.');
}
if (!str_contains($policy, 'must match the application release tag without the leading v')) {
    throw new RuntimeException('Versioning policy must require VERSION and tag consistency.');
}

echo "Version metadata consistency tests passed.\n";
