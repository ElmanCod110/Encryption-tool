[CmdletBinding()]
param([Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()][string]$PackagePath)
$ErrorActionPreference = 'Stop'
$maxHeader = 2MB
$maxIcon = 128KB
$magic = [System.Text.Encoding]::ASCII.GetBytes("SPK13BIN1" + [char]10)

function Read-U32BE([byte[]]$b, [int]$o) {
    return ([uint64]$b[$o] * 16777216) + ([uint64]$b[$o+1] * 65536) + ([uint64]$b[$o+2] * 256) + [uint64]$b[$o+3]
}
function Assert-Ico([byte[]]$b) {
    if ($b.Length -lt 22 -or $b.Length -gt $maxIcon) { throw 'Embedded ICO size is outside allowed bounds.' }
    if ([BitConverter]::ToUInt16($b,0) -ne 0 -or [BitConverter]::ToUInt16($b,2) -ne 1) { throw 'Embedded icon is not an ICO container.' }
    $count = [int][BitConverter]::ToUInt16($b,4)
    if ($count -lt 1 -or $count -gt 256 -or 6 + $count*16 -gt $b.Length) { throw 'Embedded ICO directory is invalid.' }
    $directoryEnd = 6 + $count*16
    for ($i=0; $i -lt $count; $i++) {
        $entry = 6 + $i*16
        $size = [long][BitConverter]::ToUInt32($b,$entry+8)
        $offset = [long][BitConverter]::ToUInt32($b,$entry+12)
        if ($size -lt 1 -or $offset -lt $directoryEnd -or $offset -gt $b.Length -or $size -gt ($b.Length-$offset)) { throw 'Embedded ICO image bounds are invalid.' }
    }
}
$resolved = (Resolve-Path -LiteralPath $PackagePath -ErrorAction Stop).Path
if ([IO.Path]::GetExtension($resolved) -ine '.spk13') { throw 'Choose a .spk13 file created with embedded-icon support.' }
$stream = [IO.File]::OpenRead($resolved)
try {
    if ($stream.Length -lt 14) { throw 'SPK13 file is too short.' }
    $prefix = New-Object byte[] 14
    if ($stream.Read($prefix,0,14) -ne 14) { throw 'Unable to read SPK13 header prefix.' }
    for ($i=0; $i -lt $magic.Length; $i++) { if ($prefix[$i] -ne $magic[$i]) { throw 'File does not have the SPK13 magic header.' } }
    $length = [long](Read-U32BE $prefix 10)
    if ($length -lt 2 -or $length -gt $maxHeader -or $length -gt ($stream.Length-14)) { throw 'SPK13 header length is invalid.' }
    $headerBytes = New-Object byte[] ([int]$length)
    if ($stream.Read($headerBytes,0,$headerBytes.Length) -ne $headerBytes.Length) { throw 'SPK13 header is truncated.' }
} finally { $stream.Dispose() }
try {
    $utf8 = New-Object System.Text.UTF8Encoding($false,$true)
    $header = ConvertFrom-Json -InputObject $utf8.GetString($headerBytes) -ErrorAction Stop
} catch { throw 'SPK13 header is not valid UTF-8 JSON.' }
if ($header.format -ne 'SECURE-BROWSER-V13' -or $header.version -ne 13 -or $null -eq $header.presentation -or $header.presentation.icon_format -ne 'image/x-icon' -or [string]::IsNullOrWhiteSpace([string]$header.presentation.icon_data)) { throw 'This SPK13 package does not contain supported embedded icon metadata.' }
try { $icon = [Convert]::FromBase64String([string]$header.presentation.icon_data) } catch { throw 'Embedded icon is not valid Base64.' }
Assert-Ico $icon

$cache = Join-Path $env:LOCALAPPDATA 'EncryptionTool\SPK13'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$iconPath = Join-Path $cache 'files.ico'
$temp = Join-Path $cache ([Guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($temp,$icon); Move-Item -LiteralPath $temp -Destination $iconPath -Force }
finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }

$key = 'HKCU:\Software\Classes\SystemFileAssociations\.spk13\DefaultIcon'
$statePath = 'HKCU:\Software\EncryptionTool\FileAssociations\SPK13'
$installed = '"' + $iconPath + '",0'
if (-not (Test-Path -LiteralPath $statePath)) {
    $existed = Test-Path -LiteralPath $key
    $hasPrevious = $false
    $previous = ''
    if ($existed) {
        $old = Get-Item -LiteralPath $key
        $hasPrevious = $old.GetValueNames() -contains ''
        if ($hasPrevious) { $previous = [string]$old.GetValue('') }
    }
    New-Item -Path $statePath -Force | Out-Null
    New-ItemProperty -LiteralPath $statePath -Name TargetKeyExisted -Value ([int]$existed) -PropertyType DWord -Force | Out-Null
    New-ItemProperty -LiteralPath $statePath -Name PreviousValueExists -Value ([int]$hasPrevious) -PropertyType DWord -Force | Out-Null
    New-ItemProperty -LiteralPath $statePath -Name PreviousDefaultIcon -Value $previous -PropertyType String -Force | Out-Null
}
New-Item -Path $key -Force | Out-Null
Set-Item -LiteralPath $key -Value $installed -Force
New-ItemProperty -LiteralPath $statePath -Name InstalledDefaultIcon -Value $installed -PropertyType String -Force | Out-Null
& (Join-Path $PSScriptRoot 'refresh-icons.ps1')
Write-Host 'Extracted the embedded SPK13 icon and registered it for the current Windows user.'
Write-Host "Cached icon: $iconPath"
Write-Host 'The package was read only. Run this setup on each Windows PC where Explorer should show the icon.'
