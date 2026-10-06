<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
$root = dirname(__DIR__);
$checks = [
    'legacy-branding' => ['/\bTCH\b/i','/TC_Hub/i','/TeamCode Hub/i','/tch-/i'],
    'dangerous-calls' => ['/\beval\s*\(/','/\bcreate_function\s*\(/','/(?<![:A-Za-z0-9_])passthru\s*\(/','/(?<![:A-Za-z0-9_])shell_exec\s*\(/','/(?<![:A-Za-z0-9_])system\s*\(/','/(?<![:A-Za-z0-9_])proc_open\s*\(/','/(?<![:A-Za-z0-9_])popen\s*\(/'],
    'private-key-markers' => ['/-----BEGIN PRIVATE KEY-----/','/-----BEGIN RSA PRIVATE KEY-----/','/-----BEGIN EC PRIVATE KEY-----/'],
];
$findings=[];
$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS));
foreach($it as $file){if(!$file->isFile())continue;$p=str_replace('\\','/',$file->getPathname());if(str_contains($p,'/vendor/'))continue;if($p===__FILE__)continue;if(str_contains($p,'/tests/'))continue;if(!preg_match('/\.(php|js|html|css|json|md|yml|yaml)$/i',$p))continue;$c=@file_get_contents($p);if($c===false)continue;foreach($checks as $category=>$needles){foreach($needles as $needle){if(preg_match($needle,$c) && $p!==__FILE__){$findings[]=$category.':'.$p.':'.$needle;}}}}
if($findings){echo implode(PHP_EOL,$findings).PHP_EOL;exit(1);}echo "Source audit passed.\n";
