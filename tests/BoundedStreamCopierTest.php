<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Archive\BoundedStreamCopier;

$copier = new BoundedStreamCopier();

$source = fopen('php://temp', 'w+b');
$destination = fopen('php://temp', 'w+b');
fwrite($source, '12345678');
rewind($source);
if ($copier->copy($source, $destination, 8, 8) !== 8) {
    throw new RuntimeException('Bounded copy rejected content at the exact limit.');
}
rewind($destination);
if (stream_get_contents($destination) !== '12345678') {
    throw new RuntimeException('Bounded copy changed the content.');
}
fclose($source);
fclose($destination);

foreach ([[7, 8], [8, 7]] as [$maxFile, $maxTotal]) {
    $source = fopen('php://temp', 'w+b');
    $destination = fopen('php://temp', 'w+b');
    fwrite($source, '12345678');
    rewind($source);
    $rejected = false;
    try {
        $copier->copy($source, $destination, $maxFile, $maxTotal);
    } catch (RuntimeException $error) {
        $rejected = str_contains($error->getMessage(), 'limit exceeded');
    }
    fclose($source);
    fclose($destination);
    if (!$rejected) {
        throw new RuntimeException('Bounded copy accepted content beyond its configured limit.');
    }
}

echo "Bounded archive stream tests passed.\n";
