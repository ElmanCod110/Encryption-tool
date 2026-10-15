# Windows SPK13 file icon

This optional integration registers the Encryption-tool icon for \`.spk13\` files in Windows Explorer. It does not modify encrypted files, package headers, cryptographic code, or the default application used to open files.

## Required asset

Place the project's Windows icon at:

\`\`\`text
logo/files.ico
\`\`\`

The registration script resolves this path from the repository root. It intentionally fails with a clear message if the ICO file is missing.

## Register the icon

Open PowerShell in the repository directory and run:

\`\`\`powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\file-association\register.ps1
\`\`\`

This writes to the current user's \`HKCU\` registry hive, so Administrator privileges are not required. The script records the previous icon value before changing it and notifies Windows Explorer to refresh file associations.

## Unregister / restore

Run:

\`\`\`powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\file-association\unregister.ps1
\`\`\`

The uninstaller restores the previous icon value when one was recorded. If another program changes the icon after installation, the script does not overwrite that newer value.

## Important behavior

- Only the \`.spk13\` file icon is configured.
- No file-open command or default application is registered.
- No encrypted file contents are changed.
- The icon path is stored as an absolute path. Keep the repository at that location while the registration is active; otherwise unregister the icon and register it again from the new location.
- Explorer may take a short time to refresh icons. The registration scripts send the standard association-change notification.

This feature is optional and does not affect encryption/decryption when it is not installed.

## Install using the icon embedded in a package

For a computer that does not have the repository checked out, use the installer at the repository root: `install-spk13-icon-from-package.bat`. Drag a newly created `.spk13` file onto it, or run it and provide the full package path when prompted.

The script reads only the package magic and bounded JSON header, validates the embedded ICO directory and image bounds, writes the icon to `%LOCALAPPDATA%\EncryptionTool\SPK13\files.ico`, and registers that local cached copy for the current Windows user both on the extension-specific association and, when present, the resolved extension ProgID (for example, `spk13_auto_file`). It records prior icon values and does not modify the package, change the extension-to-ProgID mapping, or change the default application. No Administrator privileges are needed.

Run this installer on each Windows computer where Explorer should display the icon. The ICO bytes travel inside the SPK13 file, but Explorer cannot extract them by itself on an unconfigured machine; this small per-user setup bridges that operating-system limitation. Use `unregister.ps1` to restore the prior icon association.

### Windows `Open with` / VS Code limitation

Windows can store a per-user choice for `.spk13` under `Explorer\\FileExts\\.spk13\\UserChoice`. If that choice points directly to an application such as `Applications\\Code.exe`, Explorer may use that application's registered icon instead of the extension-specific or extension-ProgID icon. In that case, installing the embedded ICO can succeed while Explorer continues showing the VS Code icon.

The installer detects this mismatch and prints a warning. It deliberately does not edit the protected `UserChoice` value or change the global icon for VS Code, because either a manual override of the protected association or changing VS Code's shared icon could break or affect other file types. Windows does not provide a supported registry-only per-extension override for an app-level `UserChoice` selection. Therefore, when `.spk13` is explicitly associated with VS Code this installer cannot guarantee a custom Explorer icon while leaving that association completely untouched.

The installer also pins the extracted ICO to the SHA-256 digest of the reviewed project icon. This is deliberate because the SPK13 presentation field is not cryptographically authenticated; arbitrary image bytes from an untrusted package are not passed to Explorer.
