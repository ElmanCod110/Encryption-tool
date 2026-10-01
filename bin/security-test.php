<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$fast = in_array('--full', $argv, true) === false;
$fastTests = [
    'CanonicalFuzzTest.php', 'CanonicalJsonTest.php', 'ReplayGuardTest.php', 'ReplayRaceTest.php',
    'SecurityDiagnosticsTest.php', 'SourceSecurityAuditTest.php', 'V13DescriptorTest.php', 'V13UploadTest.php', 'V14DescriptorTest.php', 'V14HeaderBindingTest.php', 'V14RecoveryTest.php', 'V14TamperHeaderTest.php', 'V14BlobTamperTest.php', 'V14RestoreSafetyTest.php', 'V14PackageRoundTripTest.php', 'V14PackageArchiveTest.php', 'ReleaseVerifierTrustRootTest.php',
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
echo ($fast ? 'All fast security tests' : 'All regression tests') . " passed.\n";
