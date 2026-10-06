<?php
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
use SecurePackage\Crypto\MerkleTree;
$leaves=[];for($i=0;$i<7;$i++)$leaves[]=hash('sha256','leaf-'.$i);
$root=MerkleTree::root($leaves);
foreach($leaves as $i=>$leaf){$proof=MerkleTree::proof($leaves,$i);if(!MerkleTree::verify($leaf,$proof,$root))throw new RuntimeException('Merkle proof failed.');}
if(MerkleTree::verify(hash('sha256','evil'),MerkleTree::proof($leaves,0),$root))throw new RuntimeException('Invalid Merkle proof accepted.');
echo "Merkle proof tests passed.\n";
