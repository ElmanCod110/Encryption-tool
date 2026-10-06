<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Client\BrowserV8;
use SecurePackage\Security\WebSecurity;
WebSecurity::startSession(); WebSecurity::applyHeaders();
header('Content-Type: application/json; charset=utf-8');
echo json_encode(BrowserV8::descriptor(), JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT);
