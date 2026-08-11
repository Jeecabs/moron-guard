# Moron Guard

<p align="center">
  <img src="https://raw.githubusercontent.com/Jeecabs/moron-guard/main/assets/moron-guard.png" alt="Moron Guard mascot blocking a terminal command" width="360">
</p>

Moron Guard is a [Pi](https://github.com/earendil-works/pi) extension. It checks shell commands for destructive operations before Pi runs them. Its TypeScript scanner runs in process and does not invoke an external scanner.

[destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) inspired the project. Moron Guard is an independent implementation and does not include or depend on that project.

> [!WARNING]
> Moron Guard is a guardrail, not a sandbox. It can miss destructive behavior in generated scripts, unrecognized interpreters, alternate tools, or unknown syntax. Use operating-system or container isolation when you need a security boundary. Review commands before you run them.

## What it checks

When enabled, Moron Guard inspects:

- `bash` tool calls made by the model
- commands entered through Pi's `!` and `!!` shortcuts
- nested commands passed through wrappers such as `sh -c`, `bash -c`, `env`, `sudo`, `doas`, `timeout`, `xargs`, and `find -exec`
- executable substitutions and interpreter payloads, while distinguishing them from quoted, search, and heredoc data

Built-in rules cover destructive filesystem, Git, system, permission, database, container, Kubernetes, cloud, remote, and package-manager operations. Findings include a rule ID, severity, confidence, evidence, and remediation.

The evaluator does not execute the command that it checks. Its decision path does not start subprocesses or use network and filesystem probes. It rejects input over 256 KiB by default and bounds nested parsing. It returns an error for malformed or opaque dynamic shell syntax. The Pi extension blocks those errors by default.

## Requirements

- Node.js 22 or later
- [Pi](https://github.com/earendil-works/pi)
- Git for installation from this repository

## Install

Review the source before installing: Pi extensions run with your full user permissions.

```bash
pi install npm:moron-guard@0.1.0
```

Versioned installs stay pinned. You can also install the matching Git tag after reviewing its source:

```bash
pi install git:github.com/Jeecabs/moron-guard@v0.1.0
```

Restart Pi after installation. To try the extension without adding it to Pi's settings:

```bash
pi -e npm:moron-guard@0.1.0
```

To remove it:

```bash
pi remove npm:moron-guard
```

## Commands

```text
/moron status
/moron doctor
/moron rules
/moron explain git reset --hard HEAD
/moron reload
/moron clear-cache
/moron off
/moron on
```

The guard starts enabled. `/moron off` disables it for the current session. Pi stores this state in the session history. `/moron on` enables the guard again.

## Configuration

Moron Guard reads global configuration first, then project configuration:

1. `~/.pi/agent/moron-guard.json` (or `$PI_AGENT_DIR/moron-guard.json`)
2. `.pi/moron-guard.json` in the current project

The legacy project path `.moron-guard.json` is accepted when `.pi/moron-guard.json` does not exist. Set `MORON_GUARD_CONFIG` to use one explicit file instead. Environment variables override file values. Run `/moron reload` after changing configuration.

```json
{
  "enabled": true,
  "mode": "enforce",
  "failClosed": true,
  "userBash": true,
  "categories": ["filesystem", "git", "database"],
  "allow": ["git status"],
  "maxDepth": 8,
  "maxCommandBytes": 262144
}
```

Modes:

- `enforce`: block deny decisions and evaluation errors when `failClosed` is true
- `audit`: evaluate commands without blocking them
- `off`: skip evaluation

By default, project configuration can only strengthen the core switches. It can set `enabled`, `mode: "enforce"`, `failClosed`, or `userBash` to safe values. Moron Guard ignores project allowlists, category filters, parser limits, and weakening switch values. Set `MORON_GUARD_ALLOW_PROJECT_CONFIG=1` only when you trust the project. This setting applies its complete configuration. Global configuration, explicit configuration, and environment variables remain trusted policy sources.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `MORON_GUARD_CONFIG` | Path to one explicit config file |
| `MORON_GUARD_ENABLED` | Enable or disable the guard |
| `MORON_GUARD_MODE` | `enforce`, `audit`, or `off` |
| `MORON_GUARD_FAIL_CLOSED` | Block evaluation errors |
| `MORON_GUARD_USER_BASH` | Inspect Pi `!` and `!!` commands |
| `MORON_GUARD_CATEGORIES` | Comma-separated rule families |
| `MORON_GUARD_ALLOW` | Semicolon-separated exact normalized commands |
| `MORON_GUARD_MAX_DEPTH` | Nested parse depth from 1 through 32 |
| `MORON_GUARD_MAX_COMMAND_BYTES` | UTF-8 input limit from 1 KiB through 1 MiB |
| `MORON_GUARD_ALLOW_PROJECT_CONFIG` | Trust and apply all project configuration fields |

Boolean environment values accept `1`, `true`, `on`, or `yes`, and `0`, `false`, `off`, or `no`, without regard to case.

Allowlisting uses exact normalized-command matching. It does not evaluate regular expressions. Keep allowlists narrow: an allowlisted command bypasses findings for that command.

## Built-in rule families

- `filesystem`: recursive removal, secure deletion, and `find -delete`
- `git`: hard reset, clean, path restore or checkout, stash deletion, branch deletion, force push, and recovery-data expiration
- `system`: block-device writes or formatting, disk erase, service stop, and destructive inline interpreter behavior
- `permissions`: broad recursive or world-writable permission changes
- `database`: destructive SQL and database CLI operations
- `containers`: destructive Docker and Compose operations
- `kubernetes`: broad namespace or resource deletion
- `cloud`: recursive object deletion and destructive provider commands
- `remote`: `rsync` deletion
- `package-manager`: destructive cache, store, and publication operations

Use `/moron rules` for the enabled family names and `/moron explain <command>` to inspect a decision without running the command.

## Host-independent API

You can use the evaluator without Pi:

```ts
import { createGuard } from "moron-guard";

const guard = createGuard({ context: { cwd: process.cwd() } });
const decision = guard.evaluate("git reset --hard HEAD");

if (decision.enforce) {
  throw new Error(`Command rejected: ${decision.action}`);
}
```

A decision has an `action` of `allow`, `deny`, or `error`, an `enforce` compatibility boolean, `source: "native"`, and structured `diagnostics`. Treat `error` as blocking unless your host explicitly implements a fail-open policy.

## Development

```bash
git clone https://github.com/Jeecabs/moron-guard.git
cd moron-guard
pnpm install --frozen-lockfile
pnpm check
pnpm test
pi -e ./src/index.ts
```

The tests parse and evaluate command strings. They do not execute candidate commands. See [CONTRIBUTING.md](CONTRIBUTING.md) before you submit a change. Maintainers should follow [RELEASING.md](RELEASING.md) when they publish a version.

## Security and support

Report vulnerabilities according to [SECURITY.md](SECURITY.md). Use [SUPPORT.md](SUPPORT.md) for usage questions and ordinary bug reports.

## License

See [LICENSE](LICENSE).
