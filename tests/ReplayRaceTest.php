<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Security\ReplayGuard;
$dir=sys_get_temp_dir().'/sp-v13-race-'.bin2hex(random_bytes(5));$g=new ReplayGuard($dir);$id='race-'.bin2hex(random_bytes(12));
$fp=[];for($i=0;$i<12;$i++){ $fp[]=fopen($dir.'/p'.$i,'w+'); }
$results=[];foreach($fp as $handle){flock($handle,LOCK_EX);$ok=$g->consume($id,120);$results[]=$ok;flock($handle,LOCK_UN);fclose($handle);}if(array_sum($results)!==1)throw new RuntimeException('Replay guard accepted more than one consume.');foreach(glob($dir.'/*')?:[] as $f)@unlink($f);@rmdir($dir);echo "Replay race tests passed.\n";
