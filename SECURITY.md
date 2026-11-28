# Security Policy

## Supported versions

Signet is pre-1.0. Security fixes target the `v1.0.0-beta.3` release line, which tracks the latest
commit on `main`.

| Version | Supported |
| --- | --- |
| `v1.0.0-beta.3` | Yes |
| `main` | Yes |
| `v1.0.0-beta.2` | Critical fixes only |
| older tags | No |

There is no patched 0.1.x series; upgrade to `v1.0.0-beta.3` or `main` to receive fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/shakibdshy/signet-auth/security/advisories/new).
Include:

- the affected version or commit
- steps to reproduce
- the potential impact and a suggested fix, if you have one

You should receive an acknowledgement within three business days and an update at
least every seven days while the report is investigated. Please allow up to 30 days
for a coordinated fix and disclosure before publishing details.

Security controls in Signet are opt-in; see the [security guide](https://go-signet-auth.vercel.app/docs/security)
for the threat model and configuration.
