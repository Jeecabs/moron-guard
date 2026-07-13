# Moron Guard

Private personal [pi](https://github.com/earendil-works/pi) extension. Routes every `bash` tool call through [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) (`dcg --robot test`) before shell execution.

If dcg denies, pi blocks tool call and shows rule/reason/remediation. No destructive command reaches bash.

## Install

Install dcg first:

```bash
# Follow upstream's current installer/docs:
# https://github.com/Dicklesworthstone/destructive_command_guard
```

Install this private pi package:

```bash
pi install git:github.com/Jeecabs/moron-guard
```

Local development:

```bash
pnpm install
pi -e ./src/index.ts
```

Reload pi after changing the extension:

```text
/reload
```

## Commands

```text
/moron status
/moron off
/moron on
```

Guard starts on. `/moron off` is session-scoped and intentionally blunt.

## Config

| Variable | Default | Purpose |
| --- | --- | --- |
| `MORON_GUARD_BIN` | `dcg` | dcg executable path |
| `DCG_BIN` | fallback | Compatibility executable path |
| `MORON_GUARD_TIMEOUT_MS` | `250` | Max decision latency |
| `MORON_GUARD_FAIL_CLOSED` | unset | Set `1` to block when dcg is unavailable |

Missing/broken dcg fails open by default, matching upstream's Pi integration recipe. Set fail-closed for stricter trusted-machine operation.

## Development

```bash
pnpm check
pnpm test
```

## Scope

Moron Guard protects `bash` tool calls. It does not claim to sandbox pi, file writes, alternate tools, scripts written to disk, or commands executed outside pi. Use OS/container sandboxing for a hard security boundary.
