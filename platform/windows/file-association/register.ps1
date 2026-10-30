[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$iconPath = Join-Path $repositoryRoot 'logo\files.ico'

if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
    throw "SPKG icon is missing. Place the ICO file at '$iconPath' and run this script again."
}

$iconPath = (Resolve-Path -LiteralPath $iconPath).Path
$installedIconValue = '"' + $iconPath + '",0'

# SystemFileAssociations supplies an extension icon without taking over the
# user's default application or defining a double-click/open command.
$iconKeyPath = 'HKCU:\Software\Classes\SystemFileAssociations\.spkg\DefaultIcon'
$stateKeyPath = 'HKCU:\Software\EncryptionTool\FileAssociations\SPKG'

if (-not (Test-Path -LiteralPath $stateKeyPath)) {
    $targetKeyExisted = Test-Path -LiteralPath $iconKeyPath
    $previousValueExists = $false
    $previousValue = ''

    if ($targetKeyExisted) {
        $targetKey = Get-Item -LiteralPath $iconKeyPath
        $previousValueExists = $targetKey.GetValueNames() -contains ''
        if ($previousValueExists) {
            $previousValue = [string] $targetKey.GetValue('')
        }
    }

    New-Item -Path $stateKeyPath -Force | Out-Null
    New-ItemProperty -LiteralPath $stateKeyPath -Name 'TargetKeyExisted' -Value ([int] $targetKeyExisted) -PropertyType DWord -Force | Out-Null
    New-ItemProperty -LiteralPath $stateKeyPath -Name 'PreviousValueExists' -Value ([int] $previousValueExists) -PropertyType DWord -Force | Out-Null
    New-ItemProperty -LiteralPath $stateKeyPath -Name 'PreviousDefaultIcon' -Value $previousValue -PropertyType String -Force | Out-Null
}

New-Item -Path $iconKeyPath -Force | Out-Null
Set-Item -LiteralPath $iconKeyPath -Value $installedIconValue -Force
New-ItemProperty -LiteralPath $stateKeyPath -Name 'InstalledDefaultIcon' -Value $installedIconValue -PropertyType String -Force | Out-Null

& (Join-Path $PSScriptRoot 'refresh-icons.ps1')

Write-Host 'SPKG file icon registered for the current Windows user.'
Write-Host "Icon: $iconPath"
Write-Host 'No default application or open command was changed.'
