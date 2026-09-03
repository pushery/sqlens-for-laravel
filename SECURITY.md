# Security Policy

## Supported versions

While this package is in its `0.x` line, security fixes are released against the latest minor version only.

| Version | Supported |
|---|---|
| `0.x` (latest) | :white_check_mark: |
| older | :x: |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report them privately through GitHub's [private vulnerability reporting](https://github.com/pushery/sqlens-for-laravel/security/advisories/new) (the "Report a vulnerability" button on the repository's Security tab). Include:

- a description of the vulnerability and its impact,
- the steps to reproduce it,
- the affected version(s),
- and, if possible, a suggested fix.

You can expect an acknowledgment within **3 business days** and an assessment of the report, including a remediation timeline, within **10 business days**. We will keep you informed throughout and credit you in the release notes once a fix ships, unless you prefer to remain anonymous.

## Dependency updates

Dependencies are kept current automatically **in the development repository**, which is where this package is built and where its dependency configuration lives: [Renovate](https://docs.renovatebot.com) opens the update pull requests, and GitHub's Dependabot **alerts** flag known advisories — which Renovate turns into prioritized security updates. Every update is reviewed before it is merged, and a release carries the result here.

If you are reading this in the published package, none of that machinery is in the tree beside it: the mirror carries the shipped code and the documents around it, and is rewritten from the development repository on every release. What the paragraph above promises is still true of the package you installed — it is simply enforced somewhere you cannot see.
