<?php
declare(strict_types=1);

$path = dirname(__DIR__) . '/public/download-restored.php';
$source = (string) file_get_contents($path);
$resolve = strpos($source, '$candidateDirectory = $store->resolve($token);');
$archiveCreate = strpos($source, '(new RestoreArchive())->create($directory, $archive);');
$consume = strpos($source, '$store->consume($token)');
$read = strpos($source, '$bytesSent = readfile($archive);');
$finally = strpos($source, '} finally {');
if ($resolve === false || $archiveCreate === false || $consume === false || $read === false || $finally === false) {
    throw new RuntimeException('Could not locate restored-download lifecycle boundaries.');
}

$cleanup = substr($source, $finally);
$checks = [
    'Restore token is resolved without consumption before archive preparation' => $resolve < $archiveCreate,
    'Restore token is consumed only after archive creation succeeds' => $archiveCreate < $consume,
    'Download completion checks the number of bytes read' =>
        str_contains($source, '$downloadComplete = $bytesSent !== false && $bytesSent === $archiveSize;'),
    'Failed archive preparation or transfer does not delete restored plaintext' =>
        str_contains($cleanup, 'if ($downloadComplete) $removeTree($directory);')
        && !preg_match('/^\s*\$removeTree\(\$directory\);/m', $cleanup),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Restored download safety check failed: ' . $description);
    }
}

echo "Restored download safety tests passed.\n";
