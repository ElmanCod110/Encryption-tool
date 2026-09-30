<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\BrowserV8;
$d=BrowserV8::descriptor();
assert($d['format']===BrowserV8::FORMAT);
assert($d['version']===8);
assert($d['server_plaintext']===false);
assert($d['server_receives_credentials']===false);
assert($d['content_addressing']==='ciphertext-hash');
assert(BrowserV8::validId(str_repeat('a',48))===true);
assert(BrowserV8::validId(str_repeat('g',48))===false);
echo "V8 format tests passed.\n";
