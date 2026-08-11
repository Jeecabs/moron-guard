# Changelog

This file records notable changes to Moron Guard.

## 0.1.0 — 2026-08-12

### Added

- Native in-process shell parser and destructive-command evaluator.
- Host-independent Guard API and Pi extension adapter.
- Project and global configuration, enforce/audit/off modes, strict environment parsing, and trusted-project controls.
- Bounded decision cache, redacted diagnostics, doctor command, and adversarial security corpus.
- Cross-platform CI, npm provenance publishing, and automated GitHub releases.
- Public project documentation, security policy, contribution guide, support guide, and mascot asset.

### Security

- Fail closed on malformed or opaque dynamic shell syntax by default.
- Restrict untrusted project configuration from weakening guard policy.
- Redact secrets and user home paths from blocked-command output.
