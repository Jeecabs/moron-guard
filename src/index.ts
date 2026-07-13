import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { dcgDecision, type MoronGuardDecision } from "./decision.js";

const STATE_ENTRY = "moron-guard-state";
const STATUS_KEY = "moron-guard";

interface PersistedState {
  enabled?: unknown;
}

function bashCommand(event: { toolName: string; input: unknown }): string | undefined {
  if (event.toolName !== "bash" || !event.input || typeof event.input !== "object") return undefined;
  const command = (event.input as { command?: unknown }).command;
  return typeof command === "string" && command.trim() ? command : undefined;
}

function restoreEnabled(ctx: ExtensionContext): boolean {
  let enabled = true;
  for (const entry of ctx.sessionManager.getBranch()) {
    if (entry.type !== "custom" || entry.customType !== STATE_ENTRY) continue;
    const data = entry.data as PersistedState | undefined;
    if (data && typeof data.enabled === "boolean") enabled = data.enabled;
  }
  return enabled;
}

function formatBlock(command: string, decision: MoronGuardDecision): string {
  const lines = [`Moron Guard blocked: ${decision.reason ?? "destructive command detected"}`];
  if (decision.ruleId) lines.push(`rule: ${decision.ruleId}`);
  if (decision.packId) lines.push(`pack: ${decision.packId}`);
  if (decision.remediation) lines.push(`safer alternative: ${decision.remediation}`);
  if (decision.allowOnceCode) lines.push(`allow once: dcg allow-once ${decision.allowOnceCode}`);
  lines.push(`command: ${command}`);
  return lines.join("\n");
}

export default function moronGuardExtension(pi: ExtensionAPI): void {
  let enabled = true;
  let unavailableNoticeShown = false;

  function persist(): void {
    pi.appendEntry(STATE_ENTRY, { enabled });
  }

  function refreshStatus(ctx: ExtensionContext): void {
    if (!ctx.hasUI || !enabled) {
      ctx.ui.setStatus(STATUS_KEY, undefined);
      return;
    }
    ctx.ui.setStatus(STATUS_KEY, `${ctx.ui.theme.fg("warning", "⚠")} ${ctx.ui.theme.fg("muted", "moron guard")}`);
  }

  function notifyUnavailable(ctx: ExtensionContext, decision: MoronGuardDecision): void {
    if (unavailableNoticeShown) return;
    unavailableNoticeShown = true;
    const mode = decision.deny ? "fail-closed" : "fail-open";
    ctx.ui.notify(
      `Moron Guard: dcg unavailable (${mode}). Set MORON_GUARD_BIN or install dcg.`,
      decision.deny ? "error" : "warning",
    );
  }

  pi.registerCommand("moron", {
    description: "Moron Guard. Usage: /moron on|off|status",
    getArgumentCompletions: (prefix) => {
      const items = [
        { value: "on", label: "on", description: "Enable Moron Guard" },
        { value: "off", label: "off", description: "Disable Moron Guard for this session" },
        { value: "status", label: "status", description: "Show Moron Guard state" },
      ];
      const filtered = items.filter((item) => item.value.startsWith(prefix.toLowerCase()));
      return filtered.length ? filtered : null;
    },
    handler: async (args, ctx) => {
      const subcommand = args.trim().split(/\s+/, 1)[0]?.toLowerCase() ?? "status";
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
        ctx.ui.notify("Moron Guard off. You are now responsible for your own mistakes.", "warning");
        return;
      }
      if (subcommand === "status") {
        refreshStatus(ctx);
        ctx.ui.notify(
          `Moron Guard: ${enabled ? "on" : "off"}\ndcg: ${process.env.MORON_GUARD_BIN ?? process.env.DCG_BIN ?? "dcg"}\nerrors: fail-open by default`,
          "info",
        );
        return;
      }
      ctx.ui.notify("Usage: /moron on|off|status", "warning");
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    enabled = restoreEnabled(ctx);
    unavailableNoticeShown = false;
    refreshStatus(ctx);
  });

  pi.on("session_tree", async (_event, ctx) => {
    enabled = restoreEnabled(ctx);
    refreshStatus(ctx);
  });

  pi.on("session_shutdown", async () => {
    persist();
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return undefined;
    const command = bashCommand(event);
    if (!command) return undefined;

    const decision = await dcgDecision(command, { cwd: ctx.cwd });
    if (decision.status === "unavailable") {
      notifyUnavailable(ctx, decision);
      if (decision.deny) {
        return { block: true, reason: decision.reason ?? "Moron Guard unavailable (fail-closed mode)." };
      }
      return undefined;
    }
    if (!decision.deny) return undefined;

    return { block: true, reason: formatBlock(command, decision) };
  });
}
