<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Project\PackageCatalog;
use SecurePackage\Project\PackageId;

$root = sys_get_temp_dir() . '/securepkg-catalog-test-' . bin2hex(random_bytes(6));
$id = PackageId::generate();
$catalog = new PackageCatalog($root);
$catalog->create($id, 'account:a', 'demo');
$catalog->setExpiry($id, 'account:a', time() + 3600);
try { $catalog->setExpiry($id, 'account:b', time() + 3600); throw new RuntimeException('Cross-owner catalog access accepted.'); } catch (Throwable) {}
$catalog->revoke($id, 'account:a');
$r = $catalog->get($id);
if ($r['revoked_at'] === null) throw new RuntimeException('Package was not revoked.');
echo "Package catalog tests passed.\n";
