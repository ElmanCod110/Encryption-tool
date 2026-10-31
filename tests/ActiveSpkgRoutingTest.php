<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$controller = (string) file_get_contents($root . '/app/Api/PackageController.php');
$download = (string) file_get_contents($root . '/public/download.php');
$apiV13 = (string) file_get_contents($root . '/public/api-v13.php');
$clientV13 = (string) file_get_contents($root . '/public/client-v13.php');
$healthV13 = (string) file_get_contents($root . '/public/health-v13.php');
$vault = (string) file_get_contents($root . '/public/client-vault.html');
$main = (string) file_get_contents($root . '/public/index.php');
$config = require $root . '/bootstrap.php';
$config = require $root . '/config/config.php';
$limits = $config['limits'];

$checks = [
    'Active package creation uses the stable SPKG writer' =>
        str_contains($controller, 'new StablePackageWriter()')
        && str_contains($controller, "\$packageId . '.spkg'"),
    'Active package restore uses only the stable SPKG reader' =>
        str_contains($controller, 'new StablePackageReader()')
        && !str_contains($controller, 'V14PackageReader')
        && !str_contains($controller, 'V14PackageService')
        && str_contains($controller, '$recoveryKey, $packageId'),
    'Active download serves only .spkg without a legacy fallback' =>
        str_contains($download, ". '.spkg'")
        && !str_contains($download, '.spkg14')
        && !str_contains($download, '.spk13'),
    'Legacy V13 API returns HTTP 410 without loading its parser' =>
        str_contains($apiV13, '], 410)')
        && !str_contains($apiV13, 'V13Descriptor')
        && !str_contains($apiV13, 'ResumableUploadV13'),
    'Legacy descriptor and health endpoints are retired without loading the V13 descriptor' =>
        str_contains($clientV13, 'http_response_code(410)')
        && !str_contains($clientV13, 'V13Descriptor')
        && str_contains($healthV13, 'http_response_code(410)')
        && !str_contains($healthV13, 'V13Descriptor'),
    'Legacy browser page does not load the old parser or worker' =>
        !str_contains($vault, 'vault-v13.js')
        && !str_contains($vault, 'worker.js')
        && str_contains($vault, 'no longer supported'),
    'Main workspace no longer links the legacy browser vault' =>
        !str_contains($main, 'client-vault.html'),
    'Application metadata identifies SPKG as the active format' =>
        ($config['app']['format'] ?? null) === 'SPKG',
    'Configured archive and restore quotas stay within the SPKG grammar bounds' =>
        $limits['max_archive_entries'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_NODES
        && $limits['max_manifest_nodes'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_NODES
        && $limits['max_package_entries'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_NODES
        && $limits['max_restore_files'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_NODES
        && $limits['max_single_file_bytes'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_FILE_BYTES
        && $limits['max_total_uncompressed_bytes'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_TOTAL_PLAIN_BYTES
        && $limits['max_package_size_bytes'] <= \SecurePackage\Project\StablePackageDescriptor::MAX_PACKAGE_BYTES
        && $limits['max_upload_bytes'] <= 110 * 1024 * 1024 * 1024
        && $limits['max_active_upload_bytes_per_owner'] <= $limits['max_upload_bytes'],
];

foreach ($checks as $description => $passed) {
    if (!$passed) throw new RuntimeException('Active SPKG routing test failed: ' . $description);
}
echo "Active SPKG routing boundary tests passed.\n";
