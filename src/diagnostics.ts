import { createHash } from "node:crypto";

const MAX_DIAGNOSTIC_TEXT = 512;
const SECRET_ASSIGNMENT = /\b((?:[A-Z][A-Z0-9_]*_)?(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL)[A-Z0-9_]*)=([^\s;]+)/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const API_TOKEN = /\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b/g;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const POSIX_HOME = /(^|[\s="'`])\/(?:Users|home)\/[^/\s="'`;]+/gm;
const WINDOWS_HOME = /(^|[\s="'`])[A-Za-z]:\\Users\\[^\\\s="'`;]+/gim;

export function commandDigest(command: string): string {
  return createHash("sha256").update(command, "utf8").digest("hex").slice(0, 16);
}

export function redactDiagnosticText(value: string, maxLength = MAX_DIAGNOSTIC_TEXT): string {
  const redacted = value
    .replace(PRIVATE_KEY, "[REDACTED_PRIVATE_KEY]")
    .replace(SECRET_ASSIGNMENT, "$1=[REDACTED]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(API_TOKEN, "[REDACTED_TOKEN]")
    .replace(POSIX_HOME, "$1~")
    .replace(WINDOWS_HOME, "$1~");
  return redacted.length > maxLength ? `${redacted.slice(0, Math.max(0, maxLength - 3))}...` : redacted;
}

export function safeDiagnosticCommand(command: string): { digest: string; preview: string } {
  return { digest: commandDigest(command), preview: redactDiagnosticText(command) };
}
