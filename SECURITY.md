# Security Policy

## Supported versions

py-authz is pre-1.0-in-spirit (actively developed, API may still shift
between minor versions per the [Release Process](README.md#release-process)).
Only the latest published release on the
[Releases page](https://github.com/saladgg/py-authz/releases) is
supported with security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected security
vulnerability.** Public issues are visible to everyone, including anyone
who might exploit the report before a fix ships.

Instead, report it privately using one of:

1. **GitHub Security Advisories (preferred)** — open a
   [private security advisory](https://github.com/saladgg/py-authz/security/advisories/new)
   on this repository. This notifies the maintainer directly without
   making the report public until a fix is ready.
2. If you don't have GitHub access to file a private advisory, contact
   the maintainer ([@saladgg](https://github.com/saladgg)) directly
   through their GitHub profile.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal repro is ideal — e.g. a script using
  `py_authz.testkit` or a specific `Authz`/`AuthzEngine`/adapter call
  sequence).
- The affected version(s), if known.

### What to expect

- **Acknowledgement** within 3 business days of the report.
- An initial assessment (confirmed / not a vulnerability / needs more
  information) within 7 business days.
- If confirmed, a fix or mitigation plan, with an estimated timeline
  based on severity. Critical issues (e.g. an authorization bypass, a
  cryptographic/JWT validation flaw) are prioritized over lower-severity
  findings.
- Credit in the release notes/`CHANGELOG.md`, if you'd like it — let us
  know your preference when you report.

Thank you for helping keep py-authz and its users safe.
