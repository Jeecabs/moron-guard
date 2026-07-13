import type { ShellCommand } from "../shell-parser.ts";

export interface EvaluationContext {
  cwd?: string;
  shell?: string;
  env?: Readonly<Record<string, string | undefined>>;
  interactive?: boolean;
  repositoryRoot?: string;
}

export type RuleCategory =
  | "filesystem"
  | "git"
  | "system"
  | "permissions"
  | "database"
  | "containers"
  | "kubernetes"
  | "cloud"
  | "remote"
  | "package-manager";

export type FindingSeverity = "low" | "medium" | "high" | "critical";
export type FindingConfidence = "low" | "medium" | "high";

export interface Remediation {
  message: string;
  command?: string;
}

export interface FindingLocation {
  start: number;
  end: number;
}

export interface RuleFinding {
  ruleId: string;
  category: RuleCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  message: string;
  remediation: Remediation;
  evidence?: string;
  location?: FindingLocation;
  command?: string;
  origin?: ShellCommand["origin"];
}

export interface EvaluationOptions {
  context?: EvaluationContext;
  maxDepth?: number;
  categories?: readonly RuleCategory[];
  allow?: readonly string[];
}

export interface EvaluationResult {
  deny: boolean;
  allowed: boolean;
  findings: RuleFinding[];
  matchedRules: string[];
  highestSeverity?: FindingSeverity;
  warnings: string[];
  normalized: string;
}

export const SEVERITY_RANK: Readonly<Record<FindingSeverity, number>> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
