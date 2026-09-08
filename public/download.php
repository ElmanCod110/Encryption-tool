<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;
WebSecurity::applyHeaders();

WebSecurity::startSession();
$id = (string) ($_GET['id'] ?? '');
if (!preg_match('/^[a-f0-9]{48}$/', $id)) {
    http_response_code(404); exit('Not found.');
}
$config = require dirname(__DIR__) . '/config/config.php';
$dir = $config['storage']['packages'] . DIRECTORY_SEPARATOR . $id;
$record = $dir . DIRECTORY_SEPARATOR . 'record.json';
if (!is_file($record)) {
    http_response_code(404); exit('Not found.');
}
$data = json_decode((string) file_get_contents($record), true);
if (!is_array($data) || ($data['package_id'] ?? '') !== $id || !preg_match('/^[a-f0-9]{48}\.spkg$/', (string) ($data['file'] ?? ''))) {
    http_response_code(404); exit('Not found.');
}
$file = $dir . DIRECTORY_SEPARATOR . $data['file'];
if (!is_file($file)) {
    http_response_code(404); exit('Not found.');
}
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $id . '.spkg"');
header('Content-Length: ' . filesize($file));
header('Cache-Control: private, no-store');
readfile($file);
