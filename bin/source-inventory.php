<?php
declare(strict_types=1);

$root = realpath($argv[1] ?? dirname(__DIR__));
if ($root === false) { fwrite(STDERR, "Source root not found.\n"); exit(1); }
$files=[];
$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach($it as $file){ if(!$file->isFile()) continue; $relative=ltrim(str_replace('\\','/',substr($file->getPathname(),strlen($root))),'/'); if(str_starts_with($relative,'.git/')||str_starts_with($relative,'storage/')) continue; if(str_ends_with($relative,'.key')||str_contains($relative,'private-key')) continue; $files[$relative]=hash_file('sha256',$file->getPathname()); }
ksort($files,SORT_STRING); echo json_encode(['algorithm'=>'SHA-256','files'=>$files],JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),PHP_EOL;
