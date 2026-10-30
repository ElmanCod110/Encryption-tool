# Package Format

The active package format for the planned 1.0.0 release line is the stable binary `.spkg` format.

- Normative byte-level grammar: [STABLE-PACKAGE-FORMAT-BINARY.md](STABLE-PACKAGE-FORMAT-BINARY.md)
- Cryptographic contract and implementation constraints: [STABLE-PACKAGE-FORMAT.md](STABLE-PACKAGE-FORMAT.md)
- Compatibility and upgrade policy: [FORMAT-COMPATIBILITY.md](FORMAT-COMPATIBILITY.md)
- Deployment trust boundary: [THREAT-MODEL.md](THREAT-MODEL.md)

The historical V14 format is not another encoding of SPKG. The planned 1.0.0 application does not parse, decrypt, create, or serve legacy V14 or Browser V13 packages. Release 0.14.1 is the last release intended to open those formats. See [MIGRATION.md](MIGRATION.md) before upgrading.

Never retry a different parser after an SPKG authentication, credential, or integrity failure.
