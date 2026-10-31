[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$iconKeyPath = 'HKCU:\Software\Classes\SystemFileAssociations\.spkg\DefaultIcon'
$stateKeyPath = 'HKCU:\Software\EncryptionTool\FileAssociations\SPKG'
$registrySubKey = 'Software\Classes\SystemFileAssociations\.spkg\DefaultIcon'

if (-not (Test-Path -LiteralPath $stateKeyPath)) {
    Write-Host 'No Encryption-tool SPKG icon registration was found for the current user.'
    exit 0
}

$state = Get-ItemProperty -LiteralPath $stateKeyPath
$installedValue = [string] $state.InstalledDefaultIcon
$targetExists = Test-Path -LiteralPath $iconKeyPath

if ($targetExists) {
    $targetKey = Get-Item -LiteralPath $iconKeyPath
    $currentValueExists = $targetKey.GetValueNames() -contains ''
    $currentValue = if ($currentValueExists) { [string] $targetKey.GetValue('') } else { '' }

    # Do not overwrite a value another program/user changed after installation.
    if ($currentValueExists -and $currentValue -eq $installedValue) {
        $writableKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($registrySubKey, $true)
        if ($null -eq $writableKey) {
            throw 'Unable to open the SPKG icon registry key for restoration.'
        }

        try {
            if ([int] $state.PreviousValueExists -eq 1) {
                $writableKey.SetValue('', [string] $state.PreviousDefaultIcon, [Microsoft.Win32.RegistryValueKind]::String)
            } else {
                $writableKey.DeleteValue('', $false)
            }
        } finally {
            $writableKey.Dispose()
        }
    }

    if ([int] $state.TargetKeyExisted -eq 0) {
        $targetKey = Get-Item -LiteralPath $iconKeyPath -ErrorAction SilentlyContinue
        if ($null -ne $targetKey -and $targetKey.GetValueNames().Count -eq 0 -and $targetKey.SubKeyCount -eq 0) {
            Remove-Item -LiteralPath $iconKeyPath -Force
        }
        $parentPath = 'HKCU:\Software\Classes\SystemFileAssociations\.spkg'
        $parent = Get-Item -LiteralPath $parentPath -ErrorAction SilentlyContinue
        if ($null -ne $parent -and $parent.GetValueNames().Count -eq 0 -and $parent.SubKeyCount -eq 0) {
            Remove-Item -LiteralPath $parentPath -Force
        }
    }
}

Remove-Item -LiteralPath $stateKeyPath -Recurse -Force
& (Join-Path $PSScriptRoot 'refresh-icons.ps1')
Write-Host 'Encryption-tool SPKG icon registration has been removed.'
