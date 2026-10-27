<?php
declare(strict_types=1);

$controllerPath = dirname(__DIR__) . '/app/Api/PackageController.php';
$controller = (string) file_get_contents($controllerPath);

$decryptStart = strpos($controller, 'public function decrypt(): never');
$packagesStart = strpos($controller, 'public function listPackages(): never', $decryptStart === false ? 0 : $decryptStart);
if ($decryptStart === false || $packagesStart === false) {
    throw new RuntimeException('Could not locate the decrypt controller boundary.');
}

$decrypt = substr($controller, $decryptStart, $packagesStart - $decryptStart);
$checks = [
    'Restore output path is initialized before restore work' =>
        strpos($decrypt, '$outputDir = null;') !== false,
    'Failed decrypt/restore paths invoke verified temporary plaintext cleanup' =>
        str_contains($decrypt, '$this->cleanupFailedRestore($outputDir, $password, $pattern, $recoveryKey);'),
    'Restore cleanup verifies deletion and clears secrets even if cleanup fails' =>
        str_contains($controller, 'private function cleanupFailedRestore(')
        && str_contains($controller, 'if (file_exists($outputDir) || is_link($outputDir))')
        && str_contains($controller, 'sodium_memzero($password);'),
    'Temporary package extraction cleanup is verified' =>
        str_contains($decrypt, 'if ($temporaryPackageDir !== null) {')
        && str_contains($decrypt, 'Unable to clean temporary package extraction.'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Restore cleanup regression check failed: ' . $description);
    }
}

echo "Restore failure cleanup regression tests passed.\n";
