import { createGuard } from "./api.js";
import { loadMoronConfig } from "./config.js";
import { safeDiagnosticCommand } from "./diagnostics.js";
const STATE_ENTRY = "moron-guard-state";
const LEGACY_STATUS_KEY = "moron-guard";
function commandFromTool(event) {
    if (event.toolName !== "bash" || !event.input || typeof event.input !== "object")
        return undefined;
    const command = event.input.command;
    return typeof command === "string" && command.trim() ? command : undefined;
}
function restoreEnabled(ctx, fallback = true) {
    let enabled = fallback;
    for (const entry of ctx.sessionManager.getBranch()) {
        if (entry.type !== "custom" || entry.customType !== STATE_ENTRY)
            continue;
        const data = entry.data;
        if (data && typeof data.enabled === "boolean")
            enabled = data.enabled;
    }
    return enabled;
}
function formatDiagnostic(diagnostic) {
    const remediation = diagnostic.remediation?.message ? `\n  safer: ${diagnostic.remediation.message}` : "";
    return `- ${diagnostic.code} [${diagnostic.severity}${diagnostic.confidence ? `/${diagnostic.confidence}` : ""}]: ${diagnostic.message}${remediation}`;
}
export function formatBlock(command, decision) {
    const findings = decision.diagnostics.filter((diagnostic) => diagnostic.kind === "finding").slice(0, 4).map(formatDiagnostic).join("\n");
    const safeCommand = safeDiagnosticCommand(command);
    return [
        "MORON GUARD BLOCKED COMMAND",
        "",
        findings || "- native policy: destructive operation detected",
        "",
        `command: ${safeCommand.preview}`,
        `command id: sha256:${safeCommand.digest}`,
        "",
        "Review the command. Use /moron explain <command> for details.",
    ].join("\n");
}
function isBlocked(decision, failClosed) {
    return decision.action === "deny" || (decision.action === "error" && failClosed);
}
function notifyResult(ctx, command, decision) {
    if (decision.action === "allow") {
        ctx.ui.notify("Moron Guard: allowed.", "info");
        return;
    }
    ctx.ui.notify(decision.action === "deny" ? formatBlock(command, decision) : `Moron Guard error: ${decision.diagnostics[0]?.message ?? "evaluation failed"}`, decision.action === "deny" ? "warning" : "error");
}
export default function moronGuardExtension(pi) {
    let enabled = true;
    let config = {
        warnings: [],
        sources: [],
        options: {},
        mode: "enforce",
        failClosed: true,
        userBash: true,
        maxCommandBytes: 256 * 1024,
    };
    let guard = createGuard(config.options);
    let errorWarningShown = false;
    function rebuildGuard() {
        guard = createGuard(config.options);
        errorWarningShown = false;
    }
    function persist() {
        pi.appendEntry(STATE_ENTRY, { enabled });
    }
    function warnOnError(ctx, decision) {
        if (decision.action !== "error" || errorWarningShown)
            return;
        errorWarningShown = true;
        ctx.ui.notify(`Moron Guard evaluation error; proceeding because fail-closed is off. ${decision.diagnostics[0]?.message ?? "unknown error"}`, "warning");
    }
    function clearLegacyStatus(ctx) {
        if (!ctx.hasUI)
            return;
        // Remove the persistent footer indicator rendered by earlier versions.
        ctx.ui.setStatus(LEGACY_STATUS_KEY, undefined);
    }
    pi.registerCommand("moron", {
        description: "Moron Guard. Usage: /moron on|off|status|doctor|explain <command>|rules|reload|clear-cache",
        getArgumentCompletions: (prefix) => {
            const items = [
                { value: "on", label: "on", description: "Enable Moron Guard" },
                { value: "off", label: "off", description: "Disable Moron Guard for this session" },
                { value: "status", label: "status", description: "Show engine status" },
                { value: "doctor", label: "doctor", description: "Run local guard self-checks" },
                { value: "explain ", label: "explain <command>", description: "Evaluate a command without running it" },
                { value: "rules", label: "rules", description: "List built-in rule families" },
                { value: "reload", label: "reload", description: "Reload config" },
                { value: "clear-cache", label: "clear-cache", description: "Clear evaluator cache" },
            ];
            const filtered = items.filter((item) => item.value.startsWith(prefix.toLowerCase()));
            return filtered.length ? filtered : null;
        },
        handler: async (args, ctx) => {
            const trimmed = args.trim();
            const splitAt = trimmed.search(/\s/);
            const subcommand = (splitAt < 0 ? trimmed : trimmed.slice(0, splitAt)).toLowerCase() || "status";
            const rest = splitAt < 0 ? "" : trimmed.slice(splitAt).trim();
            const setEnabled = (next, message, level) => {
                enabled = next;
                rebuildGuard();
                persist();
                ctx.ui.notify(message, level);
            };
            const handlers = {
                on: () => setEnabled(true, "Moron Guard on.", "info"),
                enable: () => setEnabled(true, "Moron Guard on.", "info"),
                off: () => setEnabled(false, "Moron Guard off. You own the blast radius.", "warning"),
                disable: () => setEnabled(false, "Moron Guard off. You own the blast radius.", "warning"),
                rules: () => ctx.ui.notify("Built-in packs: filesystem, git, system, permissions, database, containers, kubernetes, cloud, remote, package-manager.", "info"),
                reload: () => {
                    config = loadMoronConfig(ctx.cwd);
                    rebuildGuard();
                    ctx.ui.notify(`Moron Guard config reloaded${config.path ? `: ${config.path}` : ": defaults"}.`, "info");
                },
                "clear-cache": () => {
                    guard.clearCache();
                    ctx.ui.notify("Moron Guard cache cleared.", "info");
                },
                explain: () => {
                    if (!rest)
                        return ctx.ui.notify("Usage: /moron explain <command>", "warning");
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
                    const status = guard.status();
                    ctx.ui.notify(`Moron Guard: ${enabled ? "on" : "off"}\nmode: ${config.mode}\nuser_bash: ${config.userBash ? "on" : "off"}\nfail_closed: ${config.failClosed ? "on" : "off"}\nengine: ${status.engine}/${status.implementation}\napi: ${status.apiVersion}\nparser: ${status.parser}\ncache: ${status.cache?.entries ?? 0}/${status.cache?.max ?? 0} entries, ${status.cache?.hits ?? 0} hits, ${status.cache?.misses ?? 0} misses\nconfig: ${config.path ?? "defaults"}${config.options.categories ? `\ncategories: ${config.options.categories.join(", ")}` : ""}${config.warnings.length ? `\nwarnings: ${config.warnings.join("; ")}` : ""}`, "info");
                },
            };
            const handler = handlers[subcommand];
            if (handler)
                return await handler();
            ctx.ui.notify("Usage: /moron on|off|status|doctor|explain <command>|rules|reload|clear-cache", "warning");
        },
    });
    pi.on("session_start", async (_event, ctx) => {
        config = loadMoronConfig(ctx.cwd);
        enabled = restoreEnabled(ctx, config.enabled ?? true);
        rebuildGuard();
        clearLegacyStatus(ctx);
    });
    pi.on("session_tree", async (_event, ctx) => {
        config = loadMoronConfig(ctx.cwd);
        enabled = restoreEnabled(ctx, config.enabled ?? true);
        rebuildGuard();
        clearLegacyStatus(ctx);
    });
    pi.on("session_shutdown", async (_event, ctx) => {
        clearLegacyStatus(ctx);
        persist();
    });
    pi.on("tool_call", async (event, ctx) => {
        if (!enabled || config.mode === "off")
            return undefined;
        const command = commandFromTool(event);
        if (!command)
            return undefined;
        const decision = guard.evaluate({ command, options: { context: { cwd: ctx.cwd } } });
        if (config.mode === "audit")
            return undefined;
        warnOnError(ctx, decision);
        return isBlocked(decision, config.failClosed) ? { block: true, reason: formatBlock(command, decision) } : undefined;
    });
    pi.on("user_bash", async (event, ctx) => {
        if (!enabled || !config.userBash || config.mode === "off")
            return undefined;
        const decision = guard.evaluate({ command: event.command, options: { context: { cwd: event.cwd ?? ctx.cwd } } });
        warnOnError(ctx, decision);
        if (config.mode === "audit" || !isBlocked(decision, config.failClosed))
            return undefined;
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
