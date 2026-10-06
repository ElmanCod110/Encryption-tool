<?php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

echo "Secure Package health check\n";
echo "PHP: " . PHP_VERSION . "\n";
echo "Sodium: " . (extension_loaded('sodium') ? 'enabled' : 'missing') . "\n";
echo "Zip: " . (extension_loaded('zip') ? 'enabled' : 'missing') . "\n";
echo "PDO MySQL: " . (extension_loaded('pdo_mysql') ? 'enabled' : 'missing') . "\n";
echo "Document root: " . ($_SERVER['DOCUMENT_ROOT'] ?? 'unknown') . "\n";
