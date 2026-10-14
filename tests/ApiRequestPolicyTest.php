<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Api\ApiRequestPolicy;
use SecurePackage\Api\HttpException;

$expectStatus = static function (int $expected, callable $operation): void {
    try {
        $operation();
    } catch (HttpException $exception) {
        if ($exception->statusCode !== $expected) {
            throw new RuntimeException("Expected HTTP status {$expected}, got {$exception->statusCode}.");
        }
        return;
    }
    throw new RuntimeException("Expected HTTP status {$expected}, but request policy allowed the request.");
};

ApiRequestPolicy::assertAllowed('login', 'POST', 'application/json; charset=utf-8');
ApiRequestPolicy::assertAllowed('upload-chunk', 'POST', 'application/octet-stream');
ApiRequestPolicy::assertAllowed('csrf', 'POST', '');

$expectStatus(404, static fn() => ApiRequestPolicy::assertAllowed('unknown-action', 'POST', 'application/json'));
$expectStatus(405, static fn() => ApiRequestPolicy::assertAllowed('login', 'GET', 'application/json'));
$expectStatus(415, static fn() => ApiRequestPolicy::assertAllowed('login', 'POST', 'text/plain'));
$expectStatus(415, static fn() => ApiRequestPolicy::assertAllowed('upload-chunk', 'POST', 'application/json'));

echo "API request policy regression tests passed.\n";
