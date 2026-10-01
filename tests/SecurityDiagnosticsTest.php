<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Security\SecurityDiagnostics;
$d=SecurityDiagnostics::run(dirname(__DIR__));
if(($d['version']??0)!==14) throw new RuntimeException('Diagnostics version mismatch.');
if(($d['author']??'')!=='ElmanCod110') throw new RuntimeException('Author mismatch.');
if(($d['checks']['php_version']??false)!==true) throw new RuntimeException('PHP runtime is too old.');
if(($d['checks']['sodium']??false)!==true) throw new RuntimeException('Sodium is required.');
echo "Security diagnostics tests passed.\n";
