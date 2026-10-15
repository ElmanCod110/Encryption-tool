# Windows SPK13 file icon

This optional integration registers the Encryption-tool icon for the `.spk13` extension in Windows Explorer. **Register it once per Windows user; it applies to existing and newly created `.spk13` files on that Windows account.** The icon is an Explorer file-type association, not embedded into each encrypted file, so another PC/user must register it separately.

It does not modify encrypted files, package headers, cryptographic code, or the default application used to open files.

## Quick install (recommended)

From the repository root, double-click:

```text
install-spk13-icon.bat
```

The batch file calls the PowerShell registration script and keeps the window open so you can read the result. No Administrator privileges are required because the association is stored in the current user's `HKCU` registry hive.

You can also run the script directly from PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\file-association\register.ps1
```

## Required asset

The icon must be present at:

```text
logo/files.ico
```

The registration script resolves this path from the repository root and fails with a clear message if the ICO file is missing.

## Uninstall / restore

Double-click:

```text
uninstall-spk13-icon.bat
```

Or run the PowerShell script directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\file-association\unregister.ps1
```

The uninstaller restores the previous icon value when one was recorded. If another program changes the icon after installation, the script avoids overwriting that newer value.

## Important behavior

- The registration is per Windows user, not per individual file.
- Existing and future `.spk13` files use the registered icon on that Windows account.
- No file-open command or default application is registered or changed.
- No encrypted file contents are changed.
- The icon path is stored as an absolute path. Keep the repository at that location while the registration is active; otherwise uninstall and register again from the new location.
- Explorer may take a short time to refresh icons. The scripts send the standard association-change notification.
- Windows Explorer may still show a cached icon temporarily; refresh the folder or restart Explorer if needed.

This feature is optional and does not affect encryption/decryption when it is not installed.
