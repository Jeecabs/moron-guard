# Moron Guard

Private personal [pi](https://github.com/earendil-works/pi) extension that **implements its own destructive-command scanner in TypeScript**. [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) inspired the project; Moron Guard does not shell out to it or depend on it.

## What it does

Every Pi `bash` tool call and user `!`/`!!` command passes through an in-process guard before execution. The guard:

- lexes shell words, quotes, escapes, operators, substitutions, wrappers, and heredocs without executing input;
- recursively inspects `sh -c`, `bash -c`, `env`, `sudo`, `doas`, `timeout`, `xargs`, `find -exec`, and related wrappers;
- distinguishes executable shell content from quoted/search/heredoc data;
- reports typed findings with stable rule IDs, severity, confidence, evidence, remediation;
- blocks destructive filesystem, Git, system, permission, database, container, Kubernetes, cloud, and remote operations;
- stays dependency-free at decision time — no subprocess, network, or filesystem probe in the hot path;
- rejects commands over 128 KiB UTF-8 before parsing;
- bounds recursive parsing depth and keeps decisions deterministic.

This is a guardrail, not a sandbox. A model can still write a script, invoke an unrecognized interpreter, or use an alternate execution path. Use OS/container isolation for a hard boundary.

## Install

```bash
pi install git:github.com/Jeecabs/moron-guard
```

Local development:

```bash
pnpm install
pnpm check
pnpm test
pi -e ./src/index.ts
```

Reload after edits:

```text
/reload
```

## Commands

```text
/moron status
/moron doctor
/moron rules
/moron explain git reset --hard HEAD
/moron reload
/moron off
/moron on
```

Guard starts on. `/moron off` is session-scoped and deliberately explicit.

## Configuration

Project config: `.pi/moron-guard.json` in current repo (legacy `.moron-guard.json` is accepted). Global config: `~/.pi/agent/moron-guard.json`. Reload with `/moron reload`.

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

Environment overrides:

| Variable | Purpose |
| --- | --- |
| `MORON_GUARD_CONFIG` | Explicit config path |
| `MORON_GUARD_CATEGORIES` | Comma-separated rule families to enable |
| `MORON_GUARD_ALLOW` | Semicolon-separated exact normalized commands |
| `MORON_GUARD_MODE` | `enforce`, `audit`, or `off` |
| `MORON_GUARD_FAIL_CLOSED` | Strict boolean failure policy |
| `MORON_GUARD_USER_BASH` | Strict boolean user `!`/`!!` interception toggle |
| `MORON_GUARD_MAX_DEPTH` | Nested shell parse depth, bounded to 1–32 |
| `MORON_GUARD_MAX_COMMAND_BYTES` | UTF-8 command cap, bounded to 1 KiB–1 MiB |

Allowlisting is intentionally blunt and exact-match only. Moron Guard never evaluates user-supplied regexes in its hot path.

## Built-in rule families

- `filesystem`: recursive removal, secure deletion, `find -delete`
- `git`: hard reset, clean, restore/checkout, stash deletion, branch deletion, force push, history expiration
- `system`: block-device writes/formatting, disk erase, service stop, inline interpreter process/file destruction
- `permissions`: broad recursive or world-writable chmod/chown
- `database`: DROP, TRUNCATE, unbounded DELETE/UPDATE, database CLI drops
- `containers`: Docker prune and Compose volume deletion
- `kubernetes`: broad namespace/all-resource deletion
- `cloud`: recursive S3 deletion
- `remote`: rsync deletion
- `package-manager`: forced cache/store pruning and published package removal

Rule IDs are stable enough for diagnostics and future policy configuration. New packs should add adversarial fixtures before activation.

## Host-independent API

The native engine is reusable without Pi:

```ts
import { createGuard } from "moron-guard";

const guard = createGuard({ context: { cwd: process.cwd() } });
const decision = guard.evaluate("git reset --hard HEAD");
if (decision.enforce) throw new Error("blocked");
```

Stable result fields: `action`, `enforce`, `source`, `diagnostics`. Diagnostics redact command evidence and include stable rule IDs.

## Testing philosophy

The test suite has three layers:

1. pure shell-parser contracts;
2. typed rule/evaluator tests;
3. adversarial security corpus covering quoting, obfuscation, wrappers, heredocs, inline interpreters, SQL, Git, filesystem, and false positives.

No test executes a candidate command.
