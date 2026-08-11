# Contributing

Contributions can include bug reports, test cases, documentation fixes, and focused code changes. The [Code of Conduct](CODE_OF_CONDUCT.md) applies to this project.

## Before opening an issue

- Search existing issues for the same behavior.
- Use [SUPPORT.md](SUPPORT.md) to choose the correct reporting channel.
- Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Remove secrets, credentials, personal paths, and other sensitive data from command examples and logs.

For a rule false positive or bypass, include the smallest command that reproduces it. Include the expected decision, actual decision, and relevant configuration. Do not run destructive test commands to produce a report.

## Development setup

Requirements:

- Node.js 22 or later
- pnpm 10.28.2
- Git
- Pi, when testing extension integration

```bash
git clone https://github.com/Jeecabs/moron-guard.git
cd moron-guard
pnpm install --frozen-lockfile
pnpm check
pnpm test
```

Run the extension from the checkout when you need an integration check:

```bash
pi -e ./src/index.ts
```

## Repository layout

- `src/shell-parser.ts`: shell tokenization and nested-command extraction
- `src/core/`: rule evaluation and public evaluator types
- `src/api.ts`: host-independent guard API
- `src/index.ts`: Pi extension adapter and `/moron` command
- `src/config.ts`: configuration loading and environment overrides
- `schemas/config.schema.json`: JSON Schema for configuration files
- `tests/`: parser, rule, API, configuration, security, and performance tests

## Making a change

1. Create a branch from `main`.
2. Keep the change focused. Avoid unrelated formatting or refactoring.
3. Add or update tests for behavior changes.
4. Run `pnpm check` and `pnpm test`.
5. Update user-facing documentation when commands, configuration, or behavior changes.
6. Open a pull request that explains the problem, the chosen approach, and verification performed.

### Rule and parser changes

Moron Guard handles security-sensitive input. For changes to parsing or rules:

- Add a deny test for the destructive form.
- Add nearby allow tests to control false positives.
- Include quoted, escaped, wrapped, or nested variants when relevant.
- Keep evaluation deterministic and bounded.
- Never execute a candidate command in a test.
- Preserve rule IDs unless the compatibility impact is intentional and documented.

Prefer a test that exposes a real gap over a broad rule that blocks unrelated commands.

### API and configuration changes

Keep the host-independent API free of Pi lifecycle and UI types. Update `schemas/config.schema.json`, README configuration examples, and tests together when adding or changing a configuration field.

## Pull request checklist

- [ ] Change has a clear, limited purpose.
- [ ] New behavior has positive and negative tests.
- [ ] `pnpm check` passes.
- [ ] `pnpm test` passes.
- [ ] No candidate command is executed by tests.
- [ ] Documentation and schema changes match implementation.
- [ ] Examples and logs contain no secrets or personal data.

Maintainers may ask for a smaller change or more adversarial fixtures before merging security-sensitive code.
