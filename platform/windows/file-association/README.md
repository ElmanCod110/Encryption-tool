# Windows SPKG file icon

This optional integration registers the Encryption-tool icon for \`.spkg\` files in Windows Explorer. It does not modify encrypted files, package headers, cryptographic code, or the default application used to open files.

## Required asset

Place the project's Windows icon at:

\`\`\`text
logo/files.ico
\`\`\`

The registration script resolves this path from the repository root. It intentionally fails with a clear message if the ICO file is missing. A PNG renamed to `.ico` is not a valid Windows icon container.

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

- Only the \`.spkg\` file icon is configured.
- No file-open command or default application is registered.
- No encrypted file contents are changed.
- The icon path is stored as an absolute path. Keep the repository at that location while the registration is active; otherwise unregister the icon and register it again from the new location.
- Explorer may take a short time to refresh icons. The registration scripts send the standard association-change notification.

This feature is optional and does not affect encryption/decryption when it is not installed.
