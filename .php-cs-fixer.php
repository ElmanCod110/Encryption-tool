<?php
declare(strict_types=1);
$finder=PhpCsFixer\Finder::create()->in([__DIR__.'/app',__DIR__.'/tests',__DIR__.'/bin']);
return (new PhpCsFixer\Config())->setRiskyAllowed(false)->setRules(['@PER-CS2x0'=>true,'strict_param'=>true,'strict_comparison'=>true])->setFinder($finder);
