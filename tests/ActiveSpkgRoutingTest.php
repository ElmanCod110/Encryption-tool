<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$controller = (string) file_get_contents($root . '/app/Api/PackageController.php');
$download = (string) file_get_contents($root . '/public/download.php');
$apiV13 = (string) file_get_contents($root . '/public/api-v13.php');
$vault = (string) file_get_contents($root . '/public/client-vault.html');
$main = (string) file_get_contents($root . '/public/index.php');
$config = require $root . '/bootstrap.php';
$config = require $root . '/config/config.php';

$checks = [
    'Active package creation uses the stable SPKG writer' =>
        str_contains($controller, 'new StablePackageWriter()')
        && str_contains($controller, "\$packageId . '.spkg'"),
    'Active package restore uses only the stable SPKG reader' =>
        str_contains($controller, 'new StablePackageReader()')
        && !str_contains($controller, 'V14PackageReader')
        && !str_contains($controller, 'V14PackageService'),
    'Active download serves only .spkg without a legacy fallback' =>
        str_contains($download, ". '.spkg'")
        && !str_contains($download, '.spkg14')
        && !str_contains($download, '.spk13'),
    'Legacy V13 API returns HTTP 410 without loading its parser' =>
        str_contains($apiV13, '], 410)')
        && !str_contains($apiV13, 'V13Descriptor')
        && !str_contains($apiV13, 'ResumableUploadV13'),
    'Legacy browser page does not load the old parser or worker' =>
        !str_contains($vault, 'vault-v13.js')
        && !str_contains($vault, 'worker.js')
        && str_contains($vault, 'no longer supported'),
    'Main workspace no longer links the legacy browser vault' =>
        !str_contains($main, 'client-vault.html'),
    'Application metadata identifies SPKG as the active format' =>
        ($config['app']['format'] ?? null) === 'SPKG',
];

foreach ($checks as $description => $passed) {
    if (!$passed) throw new RuntimeException('Active SPKG routing test failed: ' . $description);
}
echo "Active SPKG routing boundary tests passed.\n";
