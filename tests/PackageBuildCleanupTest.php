<?php
declare(strict_types=1);

$controllerPath = dirname(__DIR__) . '/app/Api/PackageController.php';
$controller = (string) file_get_contents($controllerPath);
$buildStart = strpos($controller, 'public function build(): never');
$decryptStart = strpos($controller, 'public function decrypt(): never', $buildStart === false ? 0 : $buildStart);
if ($buildStart === false || $decryptStart === false) throw new RuntimeException('Could not locate the package build controller boundary.');
$build = substr($controller, $buildStart, $decryptStart - $buildStart);
$cleanupHelperStart = strpos($controller, 'private function removeJobDirectory(string $jobId): void');
$removePathStart = strpos($controller, 'private function removePath(string $path): void', $cleanupHelperStart === false ? 0 : $cleanupHelperStart);
if ($cleanupHelperStart === false || $removePathStart === false) throw new RuntimeException('Could not locate the job cleanup helper.');
$cleanupHelper = substr($controller, $cleanupHelperStart, $removePathStart - $cleanupHelperStart);
$failureStart = strpos($build, '} catch (\\Throwable) {');
$failurePath = $failureStart === false ? '' : substr($build, $failureStart);
$checks = [
    'Input validation precedes the stable writer' =>
        strpos($build, 'Validator::validateProjectName') < strpos($build, 'new StablePackageWriter()')
        && strpos($build, 'Validator::validatePassword') < strpos($build, 'new StablePackageWriter()')
        && strpos($build, 'Validator::validatePattern') < strpos($build, 'new StablePackageWriter()'),
    'SPKG is written to a single .spkg file' =>
        str_contains($build, "\$packageId . '.spkg'")
        && str_contains($build, 'new StablePackageWriter()'),
    'The plaintext job is removed only after catalog creation' =>
        strpos($build, '$this->catalog->create(') < strpos($build, '$this->removeJobDirectory($jobId);')
        && strpos($build, '$this->removeJobDirectory($jobId);') < strpos($build, "'ok' => true"),
    'Failed build cleanup preserves the plaintext source job' =>
        $failureStart !== false && !str_contains($failurePath, '$this->removeJobDirectory($jobId);'),
    'Failed build cleanup removes only the incomplete SPKG before catalog commit' =>
        str_contains($failurePath, 'if (!$packageCreated')
        && str_contains($failurePath, 'is_file($packagePath)')
        && str_contains($failurePath, '@unlink($packagePath)'),
    'Cleanup verifies that the plaintext job path is gone' =>
        str_contains($cleanupHelper, 'if (file_exists($path) || is_link($path)'),
];
foreach ($checks as $description => $passed) {
    if (!$passed) throw new RuntimeException('Package build cleanup regression check failed: ' . $description);
}
echo "SPKG build cleanup regression tests passed.\n";
