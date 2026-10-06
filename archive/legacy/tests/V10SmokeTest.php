<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\V10Descriptor;
if (V10Descriptor::FORMAT !== 'SECURE-BROWSER-V10') throw new RuntimeException('V10 format mismatch.');
if (V10Descriptor::VERSION !== 10) throw new RuntimeException('V10 version mismatch.');
if (V10Descriptor::MAGIC !== 'SPK10BIN1') throw new RuntimeException('V10 magic mismatch.');
$d=V10Descriptor::descriptor();
foreach(['key_schedule','content_encryption','integrity','chunking'] as $k) if(!isset($d[$k])) throw new RuntimeException('Missing V10 descriptor field: '.$k);
echo "V10 descriptor smoke test passed.\n";
