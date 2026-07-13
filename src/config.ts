import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import type { EvaluationOptions, RuleCategory } from "./core/index.ts";

const CATEGORIES: readonly RuleCategory[] = [
  "filesystem", "git", "system", "permissions", "database", "containers", "kubernetes", "cloud", "remote", "package-manager",
];
const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_COMMAND_BYTES = 256 * 1024;

export type MoronMode = "enforce" | "audit" | "off";

interface MoronConfigFile {
  enabled?: boolean;
  mode?: MoronMode;
  failClosed?: boolean;
  userBash?: boolean;
  categories?: string[];
  allow?: string[];
  maxDepth?: number;
  maxCommandBytes?: number;
}

export interface LoadedMoronConfig {
  path?: string;
  sources: string[];
  warnings: string[];
  options: EvaluationOptions;
  enabled?: boolean;
  mode: MoronMode;
  failClosed: boolean;
  userBash: boolean;
  maxCommandBytes: number;
}

function validCategories(values: unknown): RuleCategory[] | undefined {
  if (!Array.isArray(values)) return undefined;
  const categories = values.filter((value): value is RuleCategory => typeof value === "string" && CATEGORIES.includes(value as RuleCategory));
  return categories.length > 0 ? categories : undefined;
}

function readJson(path: string): MoronConfigFile | undefined {
  try {
    if (!existsSync(path) || readFileSync(path, "utf8").length > 256 * 1024) return undefined;
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    return parsed as MoronConfigFile;
  } catch {
    return undefined;
  }
}

function boolEnv(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  if (["1", "true", "on", "yes"].includes(value.trim().toLowerCase())) return true;
  if (["0", "false", "off", "no"].includes(value.trim().toLowerCase())) return false;
  return undefined;
}

function modeEnv(value: string | undefined): MoronMode | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized === "enforce" || normalized === "audit" || normalized === "off" ? normalized : undefined;
}

function merge(base: MoronConfigFile, next: MoronConfigFile): MoronConfigFile {
  return {
    ...base,
    ...next,
    categories: next.categories ?? base.categories,
    allow: next.allow ?? base.allow,
  };
}

export function loadMoronConfig(cwd: string, env: NodeJS.ProcessEnv = process.env): LoadedMoronConfig {
  const warnings: string[] = [];
  const sources: string[] = [];
  const explicit = env.MORON_GUARD_CONFIG?.trim();
  const agentDir = env.PI_AGENT_DIR?.trim() || join(homedir(), ".pi", "agent");
  const globalPath = join(agentDir, "moron-guard.json");
  const projectPath = join(cwd, ".pi", "moron-guard.json");
  const legacyProjectPath = join(cwd, ".moron-guard.json");
  let merged: MoronConfigFile = {};
  let selectedPath: string | undefined;

  const paths = explicit ? [resolve(cwd, explicit)] : [globalPath, existsSync(projectPath) ? projectPath : legacyProjectPath];
  for (const path of paths) {
    if (!existsSync(path)) {
      if (explicit) warnings.push(`Could not read MORON_GUARD_CONFIG: ${path}`);
      continue;
    }
    const config = readJson(path);
    if (!config) {
      warnings.push(`Invalid or oversized config ignored: ${path}`);
      continue;
    }
    merged = merge(merged, config);
    sources.push(path);
    selectedPath = path;
  }

  const projectConfig = sources.some((path) => path === projectPath || path === legacyProjectPath);
  const allowProjectWeakening = boolEnv(env.MORON_GUARD_ALLOW_PROJECT_CONFIG) === true;
  const envMode = modeEnv(env.MORON_GUARD_MODE);
  const configMode = modeEnv(merged.mode);
  const mode = envMode ?? (projectConfig && !allowProjectWeakening && configMode === "off" ? "enforce" : configMode ?? "enforce");
  const configuredEnabled = typeof merged.enabled === "boolean" ? merged.enabled : undefined;
  const enabled = projectConfig && !allowProjectWeakening ? configuredEnabled === false ? undefined : configuredEnabled : configuredEnabled;
  if (projectConfig && configuredEnabled === false && !allowProjectWeakening) warnings.push("Project enabled=false ignored; set MORON_GUARD_ALLOW_PROJECT_CONFIG=1 to weaken policy.");
  if (projectConfig && (configMode === "off" || merged.failClosed === false) && !allowProjectWeakening) warnings.push("Project weakening policy ignored without MORON_GUARD_ALLOW_PROJECT_CONFIG=1.");

  const envCategories = env.MORON_GUARD_CATEGORIES?.split(",").map((item) => item.trim());
  const categories = validCategories(envCategories ?? merged.categories);
  const allow = env.MORON_GUARD_ALLOW
    ? env.MORON_GUARD_ALLOW.split(";").map((item) => item.trim()).filter(Boolean)
    : Array.isArray(merged.allow) ? merged.allow.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : undefined;
  const parsedDepth = Number(env.MORON_GUARD_MAX_DEPTH ?? merged.maxDepth ?? DEFAULT_MAX_DEPTH);
  const maxDepth = Number.isInteger(parsedDepth) && parsedDepth >= 1 && parsedDepth <= 32 ? parsedDepth : DEFAULT_MAX_DEPTH;
  const parsedBytes = Number(env.MORON_GUARD_MAX_COMMAND_BYTES ?? merged.maxCommandBytes ?? DEFAULT_MAX_COMMAND_BYTES);
  const maxCommandBytes = Number.isInteger(parsedBytes) && parsedBytes >= 1024 && parsedBytes <= 1024 * 1024 ? parsedBytes : DEFAULT_MAX_COMMAND_BYTES;
  const envEnabled = boolEnv(env.MORON_GUARD_ENABLED);
  const envFailClosed = boolEnv(env.MORON_GUARD_FAIL_CLOSED);
  const envUserBash = boolEnv(env.MORON_GUARD_USER_BASH);
  const effectiveEnabled = envEnabled ?? enabled;
  const failClosed = envFailClosed ?? (projectConfig && !allowProjectWeakening && merged.failClosed === false ? true : merged.failClosed ?? true);
  const userBash = envUserBash ?? merged.userBash ?? true;

  for (const name of ["MORON_GUARD_BIN", "DCG_BIN", "MORON_GUARD_TIMEOUT_MS"]) {
    if (env[name]) warnings.push(`${name} is ignored; Moron Guard is in-process.`);
  }
  for (const name of ["MORON_GUARD_ENABLED", "MORON_GUARD_MODE", "MORON_GUARD_FAIL_CLOSED", "MORON_GUARD_USER_BASH"]) {
    if (env[name] !== undefined && ((name === "MORON_GUARD_MODE" && !envMode) || (name !== "MORON_GUARD_MODE" && boolEnv(env[name]) === undefined))) warnings.push(`Invalid ${name}; safe defaults retained.`);
  }

  return {
    path: selectedPath,
    sources,
    warnings,
    enabled: effectiveEnabled,
    mode,
    failClosed,
    userBash,
    maxCommandBytes,
    options: { categories, allow, maxDepth, maxCommandBytes },
  };
}
