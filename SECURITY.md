# Security Policy

Moron Guard reduces the risk of accidental execution of recognized destructive shell commands. It is not a sandbox, authorization system, or complete shell-security boundary. Run untrusted agents and commands inside an operating-system or container boundary that is appropriate for your risk.

## Supported versions

Before version 1.0, security fixes target `main` and the latest released minor version. Older releases may not receive fixes. Reproduce a report against the latest version when possible.

## Report a vulnerability

Do not open a public issue for a vulnerability or suspected bypass that could put users at risk.

Use the [GitHub private vulnerability reporting form](https://github.com/Jeecabs/moron-guard/security/advisories/new). If that form is unavailable, open an issue without exploit details or sensitive data. Ask the maintainer to start a private channel.

Include:

- affected version or commit
- operating system, Node.js version, and Pi version when relevant
- the smallest command string or API input that shows the problem
- expected and actual decisions
- relevant configuration with secrets removed
- impact and realistic attack conditions
- a suggested fix, if available

Do not execute a destructive proof of concept. A parser or evaluator result, failing test, or redacted trace is enough.

## What counts as a security report

Examples include:

- a command that reaches execution after Moron Guard should deny it
- malformed or opaque syntax that fails open under the documented default policy
- a configuration-precedence flaw that silently weakens policy
- denial of service from bounded-size input
- command evidence or diagnostics that expose secrets
- a dependency or installation flaw that permits unintended code execution

False positives, documentation errors, and unsupported command families are usually ordinary bug reports unless they create a practical security impact.

## Disclosure

Please allow maintainers time to investigate and prepare a fix before public disclosure. Maintainers will use the private report to coordinate validation, remediation, release, and credit. The project does not guarantee a response or fix timeline.
