# Support

## Usage questions

Read the [README](README.md), then run:

```text
/moron status
/moron doctor
```

`/moron status` shows the active mode, config source, parser, and cache status. `/moron doctor` checks one allowed fixture and one denied fixture. It does not execute either command.

If the problem remains, [open a GitHub issue](https://github.com/Jeecabs/moron-guard/issues) with:

- Moron Guard version or commit
- Pi and Node.js versions
- operating system
- `/moron status` and `/moron doctor` output
- relevant configuration and environment variable names
- minimal steps to reproduce
- expected and actual behavior

Remove tokens, credentials, private paths, command arguments, and other sensitive data before posting. A minimal synthetic command is preferable to a production command.

## Rule decisions

For an unexpected allow or block, include the output of:

```text
/moron explain <minimal command>
```

State whether you think the result is a false positive, a missed destructive operation, or unsupported syntax. Do not execute a destructive command to confirm a report.

## Bug reports and feature requests

Use GitHub issues for reproducible bugs and focused feature requests. Explain the problem or use case, not only the proposed implementation. Search existing issues before opening a new one.

This community project does not provide guaranteed response times or private operational support.

## Security issues

Do not post a security vulnerability or practical guard bypass in a public issue. Follow [SECURITY.md](SECURITY.md) instead.

## Conduct reports

Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for conduct concerns.
