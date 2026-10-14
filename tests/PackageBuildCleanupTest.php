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

$catchStart = strrpos($build, '} catch (\\Throwable) {');
$failurePath = $catchStart === false ? '' : substr($build, $catchStart);
$checks = [
    'Build cleanup starts only after input validation' =>
        strpos($build, 'Validator::validateProjectName') < strpos($build, '$buildStarted = true;'),
    'Successful package creation removes the plaintext job' =>
        strpos($build, '$this->catalog->create(') < strpos($build, '$this->removeJobDirectory($jobId);')
        && strpos($build, '$this->removeJobDirectory($jobId);') < strpos($build, "'ok' => true"),
    'Failed package builds attempt plaintext job cleanup' =>
        str_contains($failurePath, 'if ($buildStarted)')
        && str_contains($failurePath, '$this->removeJobDirectory($jobId);'),
    'Cleanup verifies the job path no longer exists' =>
        str_contains($cleanupHelper, 'if (file_exists($path) || is_link($path))'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Package build cleanup regression check failed: ' . $description);
    }
}

echo "Package build cleanup regression tests passed.\n";
