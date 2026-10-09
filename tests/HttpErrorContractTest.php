<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\HttpException;

$expected = new HttpException(413, 'Request body is too large.');
if ($expected->statusCode !== 413) {
    throw new RuntimeException('Expected HTTP status was not preserved.');
}
if ($expected->publicMessage !== 'Request body is too large.') {
    throw new RuntimeException('Safe public message was not preserved.');
}
if ($expected->getMessage() === $expected->publicMessage) {
    throw new RuntimeException('Internal exception details must remain separate from public messages.');
}

try {
    new HttpException(200, 'Invalid test status.');
    throw new RuntimeException('A success status was accepted as an HTTP error.');
} catch (RuntimeException $exception) {
    if ($exception->getMessage() !== 'HTTP exception status must be an error status.') {
        throw $exception;
    }
}

$api = (string) file_get_contents(dirname(__DIR__) . '/public/api.php');
$request = (string) file_get_contents(dirname(__DIR__) . '/app/Api/Request.php');
$security = (string) file_get_contents(dirname(__DIR__) . '/app/Security/WebSecurity.php');

$checks = [
    'Expected HTTP errors are handled before generic errors' =>
        strpos($api, 'catch (HttpException $exception)') < strpos($api, 'catch (Throwable $exception)'),
    'Unexpected API failures use HTTP 500' =>
        str_contains($api, "'Internal server error.'") && str_contains($api, '], 500);'),
    'Unexpected API logs do not include exception messages or traces' =>
        str_contains($api, "get_class($exception)") && !str_contains($api, '$exception->getMessage()'),
    'Oversized JSON requests use HTTP 413' =>
        str_contains($request, 'new HttpException(413,'),
    'Malformed JSON requests use HTTP 400' =>
        str_contains($request, 'new HttpException(400,'),
    'CSRF and origin failures use HTTP 403' =>
        str_contains($security, 'new HttpException(403,'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('HTTP error contract check failed: ' . $description);
    }
}

echo "HTTP error contract tests passed.\n";
