[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if (-not ('EncryptionTool.ShellNotify' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace EncryptionTool {
    public static class ShellNotify {
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(
            int eventId,
            uint flags,
            IntPtr item1,
            IntPtr item2
        );
    }
}
'@
}

# SHCNE_ASSOCCHANGED tells Explorer that file associations have changed.
[EncryptionTool.ShellNotify]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host 'Windows Explorer has been notified of the file-association change.'
