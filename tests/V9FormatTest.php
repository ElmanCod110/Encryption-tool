<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\BrowserV9;
assert(BrowserV9::FORMAT === 'SECURE-BROWSER-V9');
assert(BrowserV9::MAGIC === 'SPK9BIN1');
assert(BrowserV9::VERSION === 9);
assert(BrowserV9::validPackageId(str_repeat('a', 48)));
assert(!BrowserV9::validPackageId(str_repeat('g', 48)));
$d=BrowserV9::descriptor();
assert(($d['server_plaintext']??true)===false);
assert(($d['server_receives_credentials']??true)===false);
assert(($d['content_encryption']??'')==='AES-256-GCM');
assert(($d['integrity']??'')==='SHA-256-Merkle');
echo "V9 format tests passed.\n";
