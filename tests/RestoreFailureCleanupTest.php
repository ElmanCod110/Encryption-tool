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
    'Failed decrypt/restore paths remove temporary plaintext output' =>
        strpos($decrypt, 'if (is_string($outputDir)) $this->removePath($outputDir);') !== false,
    'Restore output cleanup happens before the error response' =>
        strpos($decrypt, '$this->removePath($outputDir);') < strpos($decrypt, "Unable to open package."),
    'Temporary package extraction cleanup remains in place' =>
        strpos($decrypt, 'if ($temporaryPackageDir !== null) $this->removePath($temporaryPackageDir);') !== false,
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Restore cleanup regression check failed: ' . $description);
    }
}

echo "Restore failure cleanup regression tests passed.\n";
