import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import type { EvaluationOptions, RuleCategory } from "./core/index.ts";

const CATEGORIES: readonly RuleCategory[] = [
  "filesystem",
  "git",
  "system",
  "permissions",
  "database",
  "containers",
  "kubernetes",
  "cloud",
  "remote",
  "package-manager",
];

export interface MoronConfigFile {
  enabled?: boolean;
  categories?: string[];
  allow?: string[];
  maxDepth?: number;
}

export interface LoadedMoronConfig {
  path?: string;
  warnings: string[];
  options: EvaluationOptions;
  enabled?: boolean;
}

function validCategories(values: unknown): RuleCategory[] | undefined {
  if (!Array.isArray(values)) return undefined;
  const categories = values.filter((value): value is RuleCategory => typeof value === "string" && CATEGORIES.includes(value as RuleCategory));
  return categories.length > 0 ? categories : undefined;
}

function readJson(path: string): MoronConfigFile | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    return parsed as MoronConfigFile;
  } catch {
    return undefined;
  }
}

export function loadMoronConfig(cwd: string, env: NodeJS.ProcessEnv = process.env): LoadedMoronConfig {
  const warnings: string[] = [];
  const configuredPath = env.MORON_GUARD_CONFIG?.trim();
  const path = configuredPath ? resolve(cwd, configuredPath) : join(cwd, ".moron-guard.json");
  const config = readJson(path);
  const exists = config !== undefined;
  if (configuredPath && !exists) warnings.push(`Could not read MORON_GUARD_CONFIG: ${path}`);

  const categories = validCategories(env.MORON_GUARD_CATEGORIES?.split(",").map((item) => item.trim()) ?? config?.categories);
  const allow = env.MORON_GUARD_ALLOW
    ? env.MORON_GUARD_ALLOW.split(";").map((item) => item.trim()).filter(Boolean)
    : Array.isArray(config?.allow) ? config.allow.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : undefined;
  const parsedDepth = Number(env.MORON_GUARD_MAX_DEPTH ?? config?.maxDepth ?? 8);
  const maxDepth = Number.isInteger(parsedDepth) && parsedDepth >= 1 && parsedDepth <= 32 ? parsedDepth : 8;

  return {
    path: exists ? path : undefined,
    warnings,
    enabled: typeof config?.enabled === "boolean" ? config.enabled : undefined,
    options: { categories, allow, maxDepth },
  };
}
