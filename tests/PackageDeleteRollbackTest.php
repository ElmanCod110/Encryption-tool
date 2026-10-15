<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$controller = (string) file_get_contents($root . '/app/Api/PackageController.php');
$tokenStore = (string) file_get_contents($root . '/app/Security/PackageAccessTokenStore.php');

$start = strpos($controller, 'public function delete(): never');
$end = strpos($controller, 'public function securityStatus(): never', $start === false ? 0 : $start);
if ($start === false || $end === false) {
    throw new RuntimeException('Could not locate the package deletion boundary.');
}
$delete = substr($controller, $start, $end - $start);

$stagePosition = strpos($delete, 'rename($originalPath, $stagedPath)');
$revokePosition = strpos($delete, '$this->accessTokens->revokeForPackage(');
$catalogDeletePosition = strpos($delete, '$this->catalog->delete(');
$checks = [
    'Both package representations are staged before access tokens are revoked' =>
        $stagePosition !== false && $revokePosition !== false && $stagePosition < $revokePosition,
    'Catalog deletion occurs only after staging and token revocation' =>
        $revokePosition !== false && $catalogDeletePosition !== false && $revokePosition < $catalogDeletePosition,
    'Partial deletion failures attempt reverse-order rollback' =>
        str_contains($delete, 'catch (\\Throwable $exception)')
        && str_contains($delete, 'array_reverse($staged)')
        && str_contains($delete, 'rename($stagedPath, $originalPath)')
        && str_contains($delete, 'original path is occupied.')
        && str_contains($delete, 'Unable to roll back interrupted package deletion.'),
    'Staged artifacts are checked after cleanup' =>
        str_contains($delete, 'Unable to clean deleted package artifacts.')
        && str_contains($delete, 'file_exists($entry[\'staged\']) || is_link($entry[\'staged\'])'),
    'Token revocation failures are no longer silently ignored' =>
        str_contains($tokenStore, 'Unable to revoke package access token.')
        && str_contains($tokenStore, 'file_exists($file) || is_link($file)'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Package deletion rollback regression failed: ' . $description);
    }
}

echo "Package deletion rollback regression tests passed.\n";
