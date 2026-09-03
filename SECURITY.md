# Security Policy

This repository is the **Privasys fork of Go**. It adds the RA-TLS challenge
extension (0xFFBB) and the RA-TLS channel binding to `crypto/tls`, used by the
Privasys platform. It is maintained by Privasys, not by the Go project.

## Reporting a vulnerability

**Do not report vulnerabilities in this fork to the Go project.** The code that
differs from upstream is ours.

Report privately, one of:

- GitHub private vulnerability reporting on this repository:
  https://github.com/Privasys/go/security/advisories/new
- Email: security@privasys.org

We acknowledge reports within three business days and keep you informed until
the issue is fixed and disclosed. Please include the release tag
(`privasys-vX.Y.Z-go1.N.M`) or commit you tested against.

If your finding concerns Go itself rather than the Privasys changes, please
follow the upstream policy at https://go.dev/security/policy.

## Supported versions

Only the latest `privasys-v*` release tag on the current `release-branch.go1.N`
branch is supported. The `master` branch mirrors upstream Go and carries no
Privasys changes.
