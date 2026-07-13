import { spawn } from "node:child_process";

const DEFAULT_TIMEOUT_MS = 250;
const MAX_OUTPUT_BYTES = 64 * 1024;

export interface MoronGuardDecision {
  status: "allowed" | "denied" | "unavailable";
  deny: boolean;
  reason?: string;
  ruleId?: string;
  packId?: string;
  remediation?: string;
  allowOnceCode?: string;
  error?: string;
}

interface DecisionPayload {
  decision?: unknown;
  allowed?: unknown;
  reason?: unknown;
  explanation?: unknown;
  remediation?: unknown;
  rule_id?: unknown;
  ruleId?: unknown;
  pack_id?: unknown;
  packId?: unknown;
  allow_once_code?: unknown;
  allowOnceCode?: unknown;
  data?: DecisionPayload;
  result?: DecisionPayload;
}

export interface DcgDecisionOptions {
  bin?: string;
  cwd?: string;
  timeoutMs?: number;
  failClosed?: boolean;
}

function stringValue(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0)?.trim();
}

function configuredTimeout(value: string | undefined): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TIMEOUT_MS;
}

function parsePayload(stdout: string): DecisionPayload | undefined {
  try {
    const parsed: unknown = JSON.parse(stdout);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    return parsed as DecisionPayload;
  } catch {
    return undefined;
  }
}

function payloadDecision(payload: DecisionPayload | undefined): "allow" | "deny" | undefined {
  const candidate = payload?.decision ?? payload?.data?.decision ?? payload?.result?.decision;
  if (typeof candidate === "string") {
    const normalized = candidate.toLowerCase();
    if (["deny", "denied", "block", "blocked"].includes(normalized)) return "deny";
    if (["allow", "allowed", "pass", "ok"].includes(normalized)) return "allow";
  }

  const allowed = payload?.allowed ?? payload?.data?.allowed ?? payload?.result?.allowed;
  if (typeof allowed === "boolean") return allowed ? "allow" : "deny";
  return undefined;
}

export function parseDcgDecision(exitCode: number | null, stdout: string): MoronGuardDecision {
  const payload = parsePayload(stdout);
  const explicitDecision = payloadDecision(payload);
  const denied = exitCode === 1 || explicitDecision === "deny";

  if (denied) {
    return {
      status: "denied",
      deny: true,
      reason: stringValue(
        payload?.reason,
        payload?.data?.reason,
        payload?.result?.reason,
        payload?.explanation,
        payload?.data?.explanation,
        payload?.result?.explanation,
      ) ?? "Destructive command detected.",
      ruleId: stringValue(payload?.rule_id, payload?.ruleId, payload?.data?.rule_id, payload?.data?.ruleId),
      packId: stringValue(payload?.pack_id, payload?.packId, payload?.data?.pack_id, payload?.data?.packId),
      remediation: stringValue(payload?.remediation, payload?.data?.remediation, payload?.result?.remediation),
      allowOnceCode: stringValue(payload?.allow_once_code, payload?.allowOnceCode, payload?.data?.allow_once_code, payload?.data?.allowOnceCode),
    };
  }

  if (exitCode === 0) return { status: "allowed", deny: false };

  return {
    status: "unavailable",
    deny: false,
    error: `dcg exited with ${exitCode === null ? "no exit code" : `code ${exitCode}`}`,
  };
}

export function dcgDecision(command: string, options: DcgDecisionOptions = {}): Promise<MoronGuardDecision> {
  const bin = options.bin ?? process.env.MORON_GUARD_BIN ?? process.env.DCG_BIN ?? "dcg";
  const timeoutMs = options.timeoutMs ?? configuredTimeout(process.env.MORON_GUARD_TIMEOUT_MS);
  const failClosed = options.failClosed ?? process.env.MORON_GUARD_FAIL_CLOSED === "1";

  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let timer: NodeJS.Timeout | undefined;

    const finish = (decision: MoronGuardDecision): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(decision);
    };

    let child;
    try {
      child = spawn(bin, ["--robot", "test", command], {
        cwd: options.cwd,
        env: { ...process.env, DCG_ROBOT: "1" },
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch (error) {
      finish({
        status: "unavailable",
        deny: failClosed,
        error: error instanceof Error ? error.message : String(error),
        reason: failClosed ? "Moron Guard unavailable (fail-closed mode)." : undefined,
      });
      return;
    }

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (stdout.length < MAX_OUTPUT_BYTES) stdout += chunk.slice(0, MAX_OUTPUT_BYTES - stdout.length);
    });
    child.once("error", (error) => {
      finish({
        status: "unavailable",
        deny: failClosed,
        error: error.message,
        reason: failClosed ? "Moron Guard unavailable (fail-closed mode)." : undefined,
      });
    });
    child.once("close", (code) => {
      if (settled) return;
      const decision = parseDcgDecision(code, stdout);
      finish(decision.status === "unavailable" && failClosed
        ? { ...decision, deny: true, reason: "Moron Guard failed to evaluate command (fail-closed mode)." }
        : decision);
    });

    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish({
          status: "unavailable",
          deny: failClosed,
          error: `dcg timed out after ${timeoutMs}ms`,
          reason: failClosed ? "Moron Guard timed out (fail-closed mode)." : undefined,
        });
      }, timeoutMs);
    }
  });
}
