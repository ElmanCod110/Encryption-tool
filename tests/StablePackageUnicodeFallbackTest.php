<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\StablePackageDescriptor as Format;

// This test also runs in the ordinary test glob. When Unicode support is installed,
// the dedicated php -n CI invocation is responsible for exercising the fallback path.
if (function_exists('mb_convert_case') && defined('MB_CASE_FOLD') && class_exists('Normalizer')) {
    echo "Stable Unicode fallback test skipped (full Unicode support is available).\n";
    exit(0);
}

try {
    Format::assertName('é.txt');
} catch (RuntimeException) {
    echo "Stable Unicode fallback rejects unsupported non-ASCII names.\n";
    exit(0);
}

throw new RuntimeException('Non-ASCII path was accepted without full normalization/case-fold support.');
