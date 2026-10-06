#!/usr/bin/env php
<?php
declare(strict_types=1);

function secret(int $length): string
{
    $lower = 'abcdefghijkmnopqrstuvwxyz';
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    $digits = '23456789';
    $special = '!@#$%^&*_-+=?';
    $pools = [$lower, $upper, $digits, $special];
    $result = '';
    foreach ($pools as $pool) {
        $result .= $pool[random_int(0, strlen($pool) - 1)];
    }
    $all = implode('', $pools);
    while (strlen($result) < $length) {
        $result .= $all[random_int(0, strlen($all) - 1)];
    }
    $chars = str_split($result);
    for ($i = count($chars) - 1; $i > 0; $i--) {
        $j = random_int(0, $i);
        [$chars[$i], $chars[$j]] = [$chars[$j], $chars[$i]];
    }
    return implode('', $chars);
}

$length = isset($argv[1]) ? max(12, min(256, (int) $argv[1])) : 24;
echo secret($length) . PHP_EOL;
