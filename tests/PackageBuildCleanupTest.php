<?php
declare(strict_types=1);

$controllerPath = dirname(__DIR__) . '/app/Api/PackageController.php';
$controller = (string) file_get_contents($controllerPath);

$buildStart = strpos($controller, 'public function build(): never');
$decryptStart = strpos($controller, 'public function decrypt(): never', $buildStart === false ? 0 : $buildStart);
if ($buildStart === false || $decryptStart === false) {
    throw new RuntimeException('Could not locate the package build controller boundary.');
}

$build = substr($controller, $buildStart, $decryptStart - $buildStart);
$cleanupHelperStart = strpos($controller, 'private function removeJobDirectory(string $jobId): void');
$removePathStart = strpos($controller, 'private function removePath(string $path): void', $cleanupHelperStart === false ? 0 : $cleanupHelperStart);
if ($cleanupHelperStart === false || $removePathStart === false) {
    throw new RuntimeException('Could not locate the job cleanup helper.');
}
$cleanupHelper = substr($controller, $cleanupHelperStart, $removePathStart - $cleanupHelperStart);

$failureStart = strpos($build, '} catch (\\Throwable $exception) {');
$cleanupFailedBuildStart = strpos($controller, 'private function cleanupFailedBuild(');
$cleanupFailedBuildEnd = strpos($controller, 'private function removeJobDirectory(', $cleanupFailedBuildStart === false ? 0 : $cleanupFailedBuildStart);
$cleanupFailedBuild = $cleanupFailedBuildStart !== false && $cleanupFailedBuildEnd !== false
    ? substr($controller, $cleanupFailedBuildStart, $cleanupFailedBuildEnd - $cleanupFailedBuildStart)
    : '';
$failurePath = $failureStart === false ? '' : substr($build, $failureStart);
$checks = [
    'Input validation precedes the encryption build' =>
        strpos($build, 'Validator::validateProjectName') < strpos($build, '$service->build(')
        && strpos($build, 'Validator::validatePassword') < strpos($build, '$service->build(')
        && strpos($build, 'Validator::validatePattern') < strpos($build, '$service->build('),
    'Successful package creation removes the plaintext job only after catalog creation' =>
        strpos($build, '$this->catalog->create(') < strpos($build, '$this->removeJobDirectory($jobId);')
        && strpos($build, '$this->removeJobDirectory($jobId);') < strpos($build, "'ok' => true"),
    'Failed builds preserve the plaintext source job for recovery' =>
        $failureStart !== false
        && !str_contains($failurePath, '$this->removeJobDirectory($jobId);')
        && !str_contains($cleanupFailedBuild, '$this->removeJobDirectory($jobId);'),
    'Incomplete encrypted artifacts are cleaned only before catalog creation' =>
        str_contains($failurePath, '$this->cleanupFailedBuild($portableArchive, $packageDirectory, $packageCreated)')
        && str_contains($cleanupFailedBuild, 'if ($packageCreated)')
        && str_contains($cleanupFailedBuild, '$this->removePath($path)')
        && str_contains($cleanupFailedBuild, 'if (file_exists($path) || is_link($path)'),
    'Cleanup verifies the job path no longer exists' =>
        str_contains($cleanupHelper, 'if (file_exists($path) || is_link($path)'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Package build cleanup regression check failed: ' . $description);
    }
}

echo "Package build cleanup regression tests passed.\\n";
