<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$releaseWorkflow = (string) file_get_contents($root . '/.github/workflows/release-security.yml');
$qaMatrix = (string) file_get_contents($root . '/docs/RELEASE-QA.md');
$releaseNotes = (string) file_get_contents($root . '/docs/RELEASE-NOTES.md');

$requirements = [
    'Release workflow must reject a missing composer.lock' =>
        str_contains($releaseWorkflow, '[ ! -f composer.lock ]'),
    'Release workflow must install locked dependencies instead of updating them' =>
        str_contains($releaseWorkflow, 'composer install --no-interaction --no-progress --prefer-dist --no-scripts'),
    'Release workflow must run the dependency audit' =>
        str_contains($releaseWorkflow, 'composer audit --no-interaction'),
    'QA matrix must distinguish unrun checks from passing checks' =>
        str_contains($qaMatrix, 'NOT RUN') && str_contains($qaMatrix, 'PASS'),
    'QA matrix must state that it is not evidence of completed manual testing' =>
        str_contains($qaMatrix, 'not a claim that the listed manual scenarios have passed'),
    'Release notes must link to the reproducible QA matrix' =>
        str_contains($releaseNotes, '[reproducible release QA matrix](RELEASE-QA.md)'),
];

$failed = false;
foreach ($requirements as $description => $passed) {
    echo ($passed ? '[PASS] ' : '[FAIL] ') . $description . PHP_EOL;
    $failed = $failed || !$passed;
}

exit($failed ? 1 : 0);
