# Security policy

## Supported versions

Security fixes go into the latest release. Update with `/plugin marketplace update zero-trust-architecture` (plugin install) or `git pull` (clone).

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/raaammm08/zero-trust-architecture/security/advisories/new). Do not open a public issue.

Include the affected file, the input that triggers the problem, and what an attacker could do with it. You should get a reply within 7 days.

## What counts as a vulnerability here

- A script that executes, writes, or deletes something it should not when given a crafted input file.
- A policy template or example that allows access it is documented to deny. Treat this one seriously: people copy these templates into production.
- A compliance mapping or reference error that would cause a control to be reported as covered when it is not.

General errors in reference material are bugs, not vulnerabilities. Report them with the [bug report form](https://github.com/raaammm08/zero-trust-architecture/issues/new/choose).
