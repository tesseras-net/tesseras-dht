# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Tesseras, please report it
responsibly through the private security mailing list:

**[~ijanc/tesseras-security@lists.sr.ht](mailto:~ijanc/tesseras-security@lists.sr.ht)**

This list is restricted to maintainers. Reports are welcome from anyone.

### Encrypting your report

Please encrypt sensitive reports using the maintainer's GPG key:

- **Key ID:** `882CF78D7F04E7F4`
- **Fingerprint:** `9C16 D725 0B23 6C1C C21A 46AB 882C F78D 7F04 E7F4`
- **Key server:** `keys.openpgp.org`

```
gpg --keyserver keys.openpgp.org --recv-keys 9C16D7250B236C1CC21A46AB882CF78D7F04E7F4
```

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected components (crate, module, function)
- Potential impact
- Suggested fix, if any

### What to expect

- Acknowledgment within 48 hours
- Status update within 7 days
- Coordinated disclosure after a fix is available

### Please do NOT

- Open a public issue or pull request for security vulnerabilities
- Disclose the vulnerability publicly before a fix is available
- Exploit the vulnerability against other users' nodes or data

## Scope

The following are in scope for security reports:

- Cryptographic issues (key generation, signing, encryption, erasure coding)
- Network protocol vulnerabilities (DHT, QUIC transport, relay)
- Authentication and authorization bypasses
- Data integrity or confidentiality violations
- Denial of service against individual nodes

## Recognition

Contributors who report valid vulnerabilities will be credited in the release
notes (unless they prefer to remain anonymous).
