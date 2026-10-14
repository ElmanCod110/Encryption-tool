<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
if (session_name() !== 'SECUREPKGSESSID') {
    throw new RuntimeException('Application session cookie name was not applied.');
}
if (ini_get('session.use_strict_mode') !== '1' || ini_get('session.use_only_cookies') !== '1' || ini_get('session.use_trans_sid') !== '0') {
    throw new RuntimeException('Strict cookie-only session settings were not applied.');
}
$params = session_get_cookie_params();
if (($params['httponly'] ?? false) !== true || ($params['samesite'] ?? '') !== 'Strict') {
    throw new RuntimeException('Session cookie security attributes were not applied.');
}
session_write_close();

echo "Web security session configuration tests passed.\n";
