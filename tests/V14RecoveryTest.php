<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Project\V14PackageBuilder;
use SecurePackage\Project\V14PackageReader;

$root = sys_get_temp_dir() . '/spk-v14-recovery-' . bin2hex(random_bytes(6));
$source = $root . '/source'; $package = $root . '/package'; $restored = $root . '/restored';
@mkdir($source, 0700, true); @mkdir($package, 0700, true);
file_put_contents($source . '/recover.txt', 'recovery-ok');
$password='Strong!Password2026#'; $pattern='Az!71_xYp#42Qw9';
try {
    $result=(new V14PackageBuilder())->build($source,$package,$password,$pattern,str_repeat('b',48),true);
    (new V14PackageReader())->restore($package,$restored,'','',$result['recovery_key']);
    if (file_get_contents($restored.'/recover.txt')!=='recovery-ok') throw new RuntimeException('Recovery restore failed.');
    echo "V14 recovery test passed.\n";
} finally {
    sodium_memzero($password); sodium_memzero($pattern);
    if(is_dir($root)){ $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST); foreach($it as $item)$item->isDir()?@rmdir($item->getPathname()):@unlink($item->getPathname()); @rmdir($root); }
}
