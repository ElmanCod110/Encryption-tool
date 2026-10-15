<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$register = (string) file_get_contents($root . '/platform/windows/file-association/register.ps1');
$unregister = (string) file_get_contents($root . '/platform/windows/file-association/unregister.ps1');
$refresh = (string) file_get_contents($root . '/platform/windows/file-association/refresh-icons.ps1');
$docs = (string) file_get_contents($root . '/platform/windows/file-association/README.md');

$checks = [
    'The ICO asset path is rooted at logo/files.ico' =>
        str_contains($register, "'logo\\files.ico'") && str_contains($docs, 'logo/files.ico'),
    'The association is per-user and scoped to SPK13' =>
        str_contains($register, 'HKCU:\Software\Classes\SystemFileAssociations\.spk13\DefaultIcon')
        && !str_contains($register, 'HKLM:\\'),
    'The feature does not replace the default application association' =>
        str_contains($register, 'without taking over')
        && !str_contains($register, 'shell\open\command')
        && !str_contains($register, "New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\.spk13'"),
    'A pre-existing icon value is recorded before installation' =>
        str_contains($register, 'PreviousDefaultIcon')
        && str_contains($register, 'PreviousValueExists')
        && str_contains($register, 'TargetKeyExisted'),
    'Unregistration only restores the value if the installed value is unchanged' =>
        str_contains($unregister, '$currentValue -eq $installedValue')
        && str_contains($unregister, 'SetValue')
        && str_contains($unregister, 'DeleteValue'),
    'Missing ICO asset fails clearly before registry changes' =>
        strpos($register, 'if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf))') !== false
        && strpos($register, "throw \"SPK13 icon is missing.") < strpos($register, 'New-Item -Path $iconKeyPath'),
    'Explorer receives the association-change notification' =>
        str_contains($refresh, 'SHChangeNotify')
        && str_contains($refresh, '0x08000000'),
    'Embedded-package installer reads SPK13 header and validates the icon before registry changes' =>
        str_contains((string) file_get_contents($root . '/platform/windows/file-association/install-from-package.ps1'), 'SPK13BIN1')
        && str_contains((string) file_get_contents($root . '/platform/windows/file-association/install-from-package.ps1'), 'Assert-Ico $icon')
        && str_contains((string) file_get_contents($root . '/platform/windows/file-association/install-from-package.ps1'), 'fe50bee47fc4929be1d2addf5097a7b010871e2cdb87a3b64023dfc78b1e214e')
        && str_contains((string) file_get_contents($root . '/platform/windows/file-association/install-from-package.ps1'), 'HKCU:\\Software\\Classes\\SystemFileAssociations\\.spk13\\DefaultIcon'),
    'Embedded-package installer is documented as per-user and package-preserving' =>
        str_contains((string) file_get_contents($root . '/platform/windows/file-association/README.md'), 'install-spk13-icon-from-package.bat')
        && str_contains((string) file_get_contents($root . '/platform/windows/file-association/README.md'), 'does not modify the selected package'),
];

foreach ($checks as $description => $passed) {
    if (!$passed) {
        throw new RuntimeException('Windows SPK13 icon integration test failed: ' . $description);
    }
}

echo "Windows SPK13 icon integration tests passed.\n";
