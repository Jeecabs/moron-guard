import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { loadMoronConfig, type LoadedMoronConfig } from "./config.ts";
import { evaluateCommand } from "./core/index.ts";
import type { EvaluationResult, RuleFinding } from "./core/index.ts";

const STATE_ENTRY = "moron-guard-state";
const STATUS_KEY = "moron-guard";
const DEFAULT_MAX_FINDINGS = 4;

interface PersistedState {
  enabled?: unknown;
}

function commandFromTool(event: { toolName: string; input: unknown }): string | undefined {
  if (event.toolName !== "bash" || !event.input || typeof event.input !== "object") return undefined;
  const command = (event.input as { command?: unknown }).command;
  return typeof command === "string" && command.trim() ? command : undefined;
}

function restoreEnabled(ctx: ExtensionContext, fallback = true): boolean {
  let enabled = fallback;
  for (const entry of ctx.sessionManager.getBranch()) {
    if (entry.type !== "custom" || entry.customType !== STATE_ENTRY) continue;
    const data = entry.data as PersistedState | undefined;
    if (data && typeof data.enabled === "boolean") enabled = data.enabled;
  }
  return enabled;
}


function formatFinding(finding: RuleFinding): string {
  return `- ${finding.ruleId} [${finding.severity}/${finding.confidence}]: ${finding.message}\n  safer: ${finding.remediation.message}`;
}

function formatBlock(command: string, result: EvaluationResult): string {
  const findings = result.findings.slice(0, DEFAULT_MAX_FINDINGS).map(formatFinding).join("\n");
  const more = result.findings.length > DEFAULT_MAX_FINDINGS ? `\n- … ${result.findings.length - DEFAULT_MAX_FINDINGS} more finding(s)` : "";
  return [
    "MORON GUARD BLOCKED COMMAND",
    "",
    findings + more,
    "",
    `command: ${command}`,
    "",
    "Review the command. Use /moron explain <command> for details.",
  ].join("\n");
}

function evaluate(command: string, ctx: ExtensionContext, config: LoadedMoronConfig): EvaluationResult {
  return evaluateCommand(command, { ...config.options, context: { cwd: ctx.cwd } });
}

function notifyResult(ctx: ExtensionContext, command: string, result: EvaluationResult): void {
  if (!result.deny) {
    ctx.ui.notify("Moron Guard: allowed.", "info");
    return;
  }
  ctx.ui.notify(formatBlock(command, result), "warning");
}

export default function moronGuardExtension(pi: ExtensionAPI): void {
  let enabled = true;
  let config: LoadedMoronConfig = { warnings: [], options: {} };

  function persist(): void {
    pi.appendEntry(STATE_ENTRY, { enabled });
  }

  function refreshStatus(ctx: ExtensionContext): void {
    if (!ctx.hasUI || !enabled) {
      ctx.ui.setStatus(STATUS_KEY, undefined);
      return;
    }
    const label = ctx.ui.theme.fg("muted", "moron guard: in-process");
    ctx.ui.setStatus(STATUS_KEY, `${ctx.ui.theme.fg("warning", "⚠")} ${label}`);
  }

  pi.registerCommand("moron", {
    description: "Moron Guard. Usage: /moron on|off|status|explain <command>|rules|reload",
    getArgumentCompletions: (prefix) => {
      const items = [
        { value: "on", label: "on", description: "Enable Moron Guard" },
        { value: "off", label: "off", description: "Disable Moron Guard for this session" },
        { value: "status", label: "status", description: "Show engine status" },
        { value: "explain ", label: "explain <command>", description: "Evaluate a command without running it" },
        { value: "rules", label: "rules", description: "List built-in rule families" },
        { value: "reload", label: "reload", description: "Reload .moron-guard.json" },
      ];
      const filtered = items.filter((item) => item.value.startsWith(prefix.toLowerCase()));
      return filtered.length ? filtered : null;
    },
    handler: async (args, ctx) => {
      const trimmed = args.trim();
      const splitAt = trimmed.search(/\s/);
      const subcommand = (splitAt < 0 ? trimmed : trimmed.slice(0, splitAt)).toLowerCase() || "status";
      const rest = splitAt < 0 ? "" : trimmed.slice(splitAt).trim();

      if (subcommand === "on" || subcommand === "enable") {
        enabled = true;
        persist();
        refreshStatus(ctx);
        ctx.ui.notify("Moron Guard on.", "info");
        return;
      }
      if (subcommand === "off" || subcommand === "disable") {
        enabled = false;
        persist();
        refreshStatus(ctx);
        ctx.ui.notify("Moron Guard off. You own the blast radius.", "warning");
        return;
      }
      if (subcommand === "rules") {
        ctx.ui.notify("Built-in packs: filesystem, git, system, permissions, database, containers, kubernetes, cloud, remote.", "info");
        return;
      }
      if (subcommand === "reload") {
        config = loadMoronConfig(ctx.cwd);
        refreshStatus(ctx);
        ctx.ui.notify(`Moron Guard config reloaded${config.path ? `: ${config.path}` : ": defaults"}.`, "info");
        return;
      }
      if (subcommand === "explain") {
        if (!rest) {
          ctx.ui.notify("Usage: /moron explain <command>", "warning");
          return;
        }
        notifyResult(ctx, rest, evaluate(rest, ctx, config));
        return;
      }
      if (subcommand === "status") {
        refreshStatus(ctx);
        ctx.ui.notify(
          `Moron Guard: ${enabled ? "on" : "off"}\nengine: in-process TypeScript scanner\nparser: shell lexer + wrappers + heredocs + substitutions\nconfig: ${config.path ?? "defaults"}${config.options.categories ? `\ncategories: ${config.options.categories.join(", ")}` : ""}${config.warnings.length ? `\nwarnings: ${config.warnings.join("; ")}` : ""}`,
          "info",
        );
        return;
      }
      ctx.ui.notify("Usage: /moron on|off|status|explain <command>|rules|reload", "warning");
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    config = loadMoronConfig(ctx.cwd);
    enabled = restoreEnabled(ctx, config.enabled ?? true);
    refreshStatus(ctx);
  });

  pi.on("session_tree", async (_event, ctx) => {
    config = loadMoronConfig(ctx.cwd);
    enabled = restoreEnabled(ctx, config.enabled ?? true);
    refreshStatus(ctx);
  });

  pi.on("session_shutdown", async () => {
    persist();
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return undefined;
    const command = commandFromTool(event);
    if (!command) return undefined;
    const result = evaluate(command, ctx, config);
    return result.deny ? { block: true, reason: formatBlock(command, result) } : undefined;
  });

  pi.on("user_bash", (event, ctx) => {
    if (!enabled) return undefined;
    const result = evaluate(event.command, ctx, config);
    if (!result.deny) return undefined;
    return {
      result: {
        output: `${formatBlock(event.command, result)}\n`,
        exitCode: 1,
        cancelled: false,
        truncated: false,
      },
    };
  });
}
