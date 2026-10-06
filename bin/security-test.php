<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$fast = in_array('--full', $argv, true) === false;
$fastTests = [
    'CanonicalFuzzTest.php', 'CanonicalJsonTest.php', 'FuzzSecurityTest.php',
    'FormatDescriptorTest.php', 'ReplayGuardTest.php', 'ReplayRaceTest.php',
    'SecurityDiagnosticsTest.php', 'SourceSecurityAuditTest.php', 'V12BuildStateTest.php',
    'ZipPolicyTest.php'
];
$tests = $fast ? array_map(fn($n) => $root . '/tests/' . $n, $fastTests) : (glob($root . '/tests/*Test.php') ?: []);
sort($tests, SORT_STRING);
$failures = [];
$start = microtime(true);
foreach ($tests as $test) {
    $output = []; $code = 0;
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($test) . ' 2>&1', $output, $code);
    echo implode(PHP_EOL, $output) . PHP_EOL;
    if ($code !== 0) $failures[] = basename($test);
}
$elapsed = microtime(true) - $start;
echo PHP_EOL . ($fast ? 'Fast security suite' : 'Full regression suite') . ' elapsed: ' . number_format($elapsed, 3) . "s\n";
if ($failures) {
    echo 'Failed tests: ' . implode(', ', $failures) . "\n";
    exit(1);
}
echo ($fast ? 'All V12 fast security tests' : 'All regression tests') . " passed.\n";
