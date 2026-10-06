<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Security\CanonicalJson;
mt_srand(202612);
for($i=0;$i<10000;$i++){
    $v=[];
    $count=mt_rand(0,20);
    for($j=0;$j<$count;$j++){
        $k='k'.mt_rand(0,100000);
        $v[$k]=match(mt_rand(0,5)){
            0=>null,
            1=>mt_rand(-PHP_INT_MAX,PHP_INT_MAX),
            2=>str_repeat(chr(mt_rand(32,126)),mt_rand(0,100)),
            3=>[mt_rand(0,100),mt_rand(0,100),mt_rand(0,100)],
            4=>(bool)mt_rand(0,1),
            default=>['nested'=>['x'=>mt_rand(0,1000)]],
        };
    }
    $a=CanonicalJson::encode($v);$b=CanonicalJson::encode($v);
    if($a!==$b) throw new RuntimeException('Non-deterministic canonical JSON.');
}
echo "Canonical fuzz tests passed.\n";
