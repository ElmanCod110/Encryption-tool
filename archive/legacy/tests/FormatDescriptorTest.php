<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\V12Descriptor;
$d=V12Descriptor::descriptor();
$required=['format','version','container_magic','footer_magic','extension','transport','server_plaintext','credentials_to_server','kdf','key_separation','content_encryption','chunk_integrity','package_integrity','chunking'];
foreach($required as $k) if(!array_key_exists($k,$d)) throw new RuntimeException('Missing descriptor field: '.$k);
if($d['format']!=='SECURE-BROWSER-V12'||$d['version']!==12||$d['server_plaintext']!==false||$d['credentials_to_server']!==false)throw new RuntimeException('Descriptor security invariant failed.');
echo "V12 format descriptor tests passed.\n";
