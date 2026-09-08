<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\ContentDefinedChunker;
$input=random_bytes(13*1024*1024+123);
$chunks=ContentDefinedChunker::split($input);
$joined=implode('', $chunks);
if (!hash_equals($input,$joined)) throw new RuntimeException('CDC round-trip failed.');
foreach($chunks as $c){if(strlen($c)>ContentDefinedChunker::MAX)throw new RuntimeException('CDC max bound failed.');}
if(count($chunks)<2)throw new RuntimeException('CDC did not split test input.');
echo "Content-defined chunking tests passed.\n";
