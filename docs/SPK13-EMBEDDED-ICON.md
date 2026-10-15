# SPK13 embedded icon metadata

SPK13 packages created by Browser Vault now carry the built-in ICO bytes in the optional `presentation` header member:

- `presentation.icon_format`: `image/x-icon`
- `presentation.icon_data`: base64-encoded ICO bytes, bounded to 128 KiB after decoding.

The metadata is presentation-only. It is **not cryptographically authenticated** by the current V13 format and must never be trusted for security decisions. The parser validates the ICO directory and all image bounds before accepting it. Packages created before this feature omit the member and remain supported.

## Windows Explorer limitation

Embedding an icon makes the icon data portable with the package, but Windows Explorer does not inspect arbitrary SPK13 headers to discover icons. Showing this icon in Explorer on another Windows machine still requires an installed file association or shell integration that can extract the embedded ICO. This feature does not silently install machine-wide integration and does not change the encrypted file payload or restore process.

## Compatibility checks

The browser round-trip test verifies that new packages include the built-in icon, packages with the optional field removed still restore, malformed icon metadata is rejected, and restored file content remains unchanged.
