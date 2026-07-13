// fallow-ignore-file unused-file
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { createGuard, type Decision, type Diagnostic, type Guard } from "./api.ts";
import { loadMoronConfig, type LoadedMoronConfig } from "./config.ts";

const STATE_ENTRY = "moron-guard-state";
const STATUS_KEY = "moron-guard";

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


function formatDiagnostic(diagnostic: Diagnostic): string {
  const remediation = diagnostic.remediation?.message ? `\n  safer: ${diagnostic.remediation.message}` : "";
  return `- ${diagnostic.code} [${diagnostic.severity}${diagnostic.confidence ? `/${diagnostic.confidence}` : ""}]: ${diagnostic.message}${remediation}`;
}

function formatBlock(command: string, decision: Decision): string {
  const findings = decision.diagnostics.filter((diagnostic) => diagnostic.kind === "finding").slice(0, 4).map(formatDiagnostic).join("\n");
  return [
    "MORON GUARD BLOCKED COMMAND",
    "",
    findings || "- native policy: destructive operation detected",
    "",
    `command: ${command}`,
    "",
    "Review the command. Use /moron explain <command> for details.",
  ].join("\n");
}

function isBlocked(decision: Decision): boolean {
  return decision.action !== "allow";
}

function notifyResult(ctx: ExtensionContext, command: string, decision: Decision): void {
  if (decision.action === "allow") {
    ctx.ui.notify("Moron Guard: allowed.", "info");
    return;
  }
  ctx.ui.notify(decision.action === "deny" ? formatBlock(command, decision) : `Moron Guard error: ${decision.diagnostics[0]?.message ?? "evaluation failed"}`, decision.action === "deny" ? "warning" : "error");
}

export default function moronGuardExtension(pi: ExtensionAPI): void {
  let enabled = true;
  let config: LoadedMoronConfig = { warnings: [], options: {} };
  let guard: Guard = createGuard(config.options);

  function rebuildGuard(): void {
    guard = createGuard(config.options);
  }

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
    description: "Moron Guard. Usage: /moron on|off|status|doctor|explain <command>|rules|reload",
    getArgumentCompletions: (prefix) => {
      const items = [
        { value: "on", label: "on", description: "Enable Moron Guard" },
        { value: "off", label: "off", description: "Disable Moron Guard for this session" },
        { value: "status", label: "status", description: "Show engine status" },
        { value: "doctor", label: "doctor", description: "Run local guard self-checks" },
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
      const setEnabled = (next: boolean, message: string, level: "info" | "warning"): void => {
        enabled = next;
        rebuildGuard();
        persist();
        refreshStatus(ctx);
        ctx.ui.notify(message, level);
      };
      const handlers: Record<string, () => void | Promise<void>> = {
        on: () => setEnabled(true, "Moron Guard on.", "info"),
        enable: () => setEnabled(true, "Moron Guard on.", "info"),
        off: () => setEnabled(false, "Moron Guard off. You own the blast radius.", "warning"),
        disable: () => setEnabled(false, "Moron Guard off. You own the blast radius.", "warning"),
        rules: () => ctx.ui.notify("Built-in packs: filesystem, git, system, permissions, database, containers, kubernetes, cloud, remote, package-manager.", "info"),
        reload: () => {
          config = loadMoronConfig(ctx.cwd);
          rebuildGuard();
          refreshStatus(ctx);
          ctx.ui.notify(`Moron Guard config reloaded${config.path ? `: ${config.path}` : ": defaults"}.`, "info");
        },
        explain: () => {
          if (!rest) return ctx.ui.notify("Usage: /moron explain <command>", "warning");
          notifyResult(ctx, rest, guard.explain({ command: rest, options: { context: { cwd: ctx.cwd } } }));
        },
        doctor: () => {
          const status = guard.status();
          const allowed = guard.decide("git status");
          const denied = guard.decide("git reset --hard HEAD");
          const healthy = status.ready && allowed.action === "allow" && denied.action === "deny";
          ctx.ui.notify([`Moron Guard doctor: ${healthy ? "healthy" : "FAILED"}`, `engine: ${status.engine}/${status.implementation}`, `safe fixture: ${allowed.action}`, `destructive fixture: ${denied.action}`, config.warnings.length ? `config warnings: ${config.warnings.join("; ")}` : "config: valid/defaults"].join("\n"), healthy ? "info" : "error");
        },
        status: () => {
          refreshStatus(ctx);
          const status = guard.status();
          ctx.ui.notify(`Moron Guard: ${enabled ? "on" : "off"}\nengine: ${status.engine}/${status.implementation}\napi: ${status.apiVersion}\nparser: ${status.parser}\nconfig: ${config.path ?? "defaults"}${config.options.categories ? `\ncategories: ${config.options.categories.join(", ")}` : ""}${config.warnings.length ? `\nwarnings: ${config.warnings.join("; ")}` : ""}`, "info");
        },
      };
      const handler = handlers[subcommand];
      if (handler) return await handler();
      ctx.ui.notify("Usage: /moron on|off|status|doctor|explain <command>|rules|reload", "warning");
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    config = loadMoronConfig(ctx.cwd);
    enabled = restoreEnabled(ctx, config.enabled ?? true);
    rebuildGuard();
    refreshStatus(ctx);
  });

  pi.on("session_tree", async (_event, ctx) => {
    config = loadMoronConfig(ctx.cwd);
    enabled = restoreEnabled(ctx, config.enabled ?? true);
    rebuildGuard();
    refreshStatus(ctx);
  });

  pi.on("session_shutdown", async () => {
    persist();
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return undefined;
    const command = commandFromTool(event);
    if (!command) return undefined;
    const decision = guard.evaluate({ command, options: { context: { cwd: ctx.cwd } } });
    return isBlocked(decision) ? { block: true, reason: formatBlock(command, decision) } : undefined;
  });

  pi.on("user_bash", async (event, ctx) => {
    if (!enabled) return undefined;
    const decision = guard.evaluate({ command: event.command, options: { context: { cwd: ctx.cwd } } });
    if (!isBlocked(decision)) return undefined;
    return {
      result: {
        output: `${formatBlock(event.command, decision)}\n`,
        exitCode: 1,
        cancelled: false,
        truncated: false,
      },
    };
  });
}
