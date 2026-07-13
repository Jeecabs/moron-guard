import { createHash } from "node:crypto";

import { redactDiagnosticText } from "./diagnostics.ts";
import { evaluateCommand } from "./core/evaluate.ts";
import type {
  EvaluationContext,
  EvaluationOptions,
  EvaluationResult,
  FindingConfidence,
  FindingLocation,
  FindingSeverity,
  Remediation,
  RuleCategory,
  RuleFinding,
} from "./core/types.ts";
import type { ShellCommandOrigin } from "./shell-parser.ts";

/** Stable actions returned by the host-independent guard boundary. */
export type DecisionAction = "allow" | "deny" | "error";

export type DiagnosticKind = "finding" | "warning" | "error";
export type DiagnosticSeverity = FindingSeverity | "info" | "error";

/**
 * A host-neutral diagnostic. Findings keep their native rule metadata while
 * exposing `code` as the stable diagnostic identifier.
 */
export interface Diagnostic {
  code: string;
  kind: DiagnosticKind;
  severity: DiagnosticSeverity;
  message: string;
  confidence?: FindingConfidence;
  category?: RuleCategory;
  remediation?: Remediation;
  evidence?: string;
  location?: FindingLocation;
  command?: string;
  origin?: ShellCommandOrigin;
  /** Native rule ID, retained as an explicit compatibility alias for code. */
  ruleId?: string;
}

/** The only result shape a host needs in order to make an execution decision. */
export interface Decision {
  action: DecisionAction;
  /** Compatibility boolean: true when host should prevent execution. */
  enforce: boolean;
  source: "native";
  diagnostics: readonly Diagnostic[];
}

/** A command request accepted by the reusable API. */
export interface GuardRequest {
  command: string;
  options?: EvaluationOptions;
}

export type GuardInput = string | GuardRequest;

/** Default evaluator options held by a Guard instance. */
export interface GuardOptions extends EvaluationOptions {
  cacheMax?: number;
  cacheTtlMs?: number;
  policyVersion?: string;
}

/** Details returned by explain, in addition to the stable Decision fields. */
export interface Explanation extends Decision {
  command: string;
  normalized: string;
  matchedRules: readonly string[];
  highestSeverity?: FindingSeverity;
}

export type ExplainResult = Explanation;

export type GuardStatusCapability = "decide" | "explain" | "status";

/** Static and configured capabilities of this evaluator implementation. */
export interface GuardStatus {
  apiVersion: "1";
  engine: "native";
  implementation: "in-process";
  parser: "shell-lexer";
  ready: true;
  categories: readonly RuleCategory[];
  maxDepth: number;
  capabilities: readonly GuardStatusCapability[];
  diagnostics: readonly Diagnostic[];
  cache?: { entries: number; hits: number; misses: number; max: number; ttlMs: number };
}

const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_CACHE_MAX = 2048;
const DEFAULT_CACHE_TTL_MS = 1000;
const ALL_CATEGORIES: readonly RuleCategory[] = [
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
const CAPABILITIES: readonly GuardStatusCapability[] = ["decide", "explain", "status"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validMaxDepth(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 32;
}

function validMaxCommandBytes(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1024 && value <= 1024 * 1024;
}

function cloneContext(context: EvaluationContext | undefined): EvaluationContext | undefined {
  if (!context) return undefined;
  return {
    ...context,
    env: context.env ? { ...context.env } : undefined,
  };
}

function normalizeOptions(options: GuardOptions = {}): GuardOptions {
  return {
    ...options,
    ...(options.maxDepth === undefined || validMaxDepth(options.maxDepth) ? {} : { maxDepth: DEFAULT_MAX_DEPTH }),
    ...(options.maxCommandBytes === undefined || validMaxCommandBytes(options.maxCommandBytes) ? {} : { maxCommandBytes: 256 * 1024 }),
    categories: options.categories ? [...options.categories] : undefined,
    allow: options.allow ? [...options.allow] : undefined,
    context: cloneContext(options.context),
    cacheMax: typeof options.cacheMax === "number" && Number.isInteger(options.cacheMax) && options.cacheMax >= 0 ? options.cacheMax : DEFAULT_CACHE_MAX,
    cacheTtlMs: typeof options.cacheTtlMs === "number" && Number.isFinite(options.cacheTtlMs) && options.cacheTtlMs >= 0 ? options.cacheTtlMs : DEFAULT_CACHE_TTL_MS,
    policyVersion: options.policyVersion ?? "native-default",
  };
}

function mergeOptions(base: GuardOptions, override: EvaluationOptions | undefined): GuardOptions {
  if (!override) return normalizeOptions(base);
  const context = base.context || override.context
    ? { ...base.context, ...override.context, env: override.context?.env ?? base.context?.env }
    : undefined;
  return normalizeOptions({
    ...base,
    ...override,
    maxDepth: override.maxDepth ?? base.maxDepth,
    categories: override.categories ?? base.categories,
    allow: override.allow ?? base.allow,
    context,
  });
}

function findingDiagnostic(finding: RuleFinding): Diagnostic {
  return {
    code: finding.ruleId,
    ruleId: finding.ruleId,
    kind: "finding",
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    message: finding.message,
    remediation: finding.remediation ? { ...finding.remediation } : undefined,
    evidence: finding.evidence ? redactDiagnosticText(finding.evidence) : undefined,
    location: finding.location ? { ...finding.location } : undefined,
    command: finding.command ? redactDiagnosticText(finding.command) : undefined,
    origin: finding.origin,
  };
}

function resultDiagnostics(result: EvaluationResult): Diagnostic[] {
  const diagnostics = result.findings.map(findingDiagnostic);
  for (const warning of result.warnings) {
    diagnostics.push({
      code: "guard.warning",
      kind: "warning",
      severity: "info",
      message: warning,
    });
  }
  return diagnostics;
}

function decisionFromResult(result: EvaluationResult): Decision {
  const diagnostics = resultDiagnostics(result);
  if (!result.deny && result.warnings.length > 0) diagnostics.push(errorDiagnostic("guard.unknown-syntax", "Shell syntax could not be classified safely."));
  const action: DecisionAction = result.deny ? "deny" : result.warnings.length > 0 ? "error" : "allow";
  return {
    action,
    enforce: action !== "allow",
    source: "native",
    diagnostics,
  };
}

function errorDiagnostic(code: string, message: string): Diagnostic {
  return { code, kind: "error", severity: "error", message };
}

function evaluationError(error: unknown): Decision {
  const detail = error instanceof Error ? error.message : String(error);
  return {
    action: "error",
    enforce: true,
    source: "native",
    diagnostics: [errorDiagnostic("guard.evaluation-error", detail ? `Guard evaluation failed: ${detail}` : "Guard evaluation failed.")],
  };
}

interface ParsedInput {
  command: string;
  options?: EvaluationOptions;
}

function parseInput(input: GuardInput): ParsedInput | Decision {
  if (typeof input === "string") return { command: input };
  if (!isRecord(input) || typeof input.command !== "string") {
    return {
      action: "error",
      enforce: true,
      source: "native",
      diagnostics: [errorDiagnostic("guard.invalid-command", "Guard command must be a string.")],
    };
  }
  if (input.options !== undefined && !isRecord(input.options)) {
    return {
      action: "error",
      enforce: true,
      source: "native",
      diagnostics: [errorDiagnostic("guard.invalid-options", "Guard options must be an object.")],
    };
  }
  return { command: input.command, options: input.options as EvaluationOptions | undefined };
}

function isDecision(value: ParsedInput | Decision): value is Decision {
  return "action" in value;
}

function explainError(input: GuardInput, decision: Decision): Explanation {
  return {
    ...decision,
    command: typeof input === "string" ? input : isRecord(input) && typeof input.command === "string" ? input.command : "",
    normalized: "",
    matchedRules: [],
  };
}

interface CacheEntry {
  decision: Decision;
  expiresAt: number;
}

function cacheKey(command: string, options: GuardOptions): string {
  const commandKey = createHash("sha256").update(command, "utf8").digest("hex");
  return `${options.policyVersion}:${commandKey}:${options.context?.cwd ?? ""}:${JSON.stringify({ categories: options.categories, allow: options.allow, maxDepth: options.maxDepth, maxCommandBytes: options.maxCommandBytes })}`;
}

/**
 * Reusable, host-independent Moron Guard API.
 *
 * It only calls the in-process native evaluator. No host lifecycle, UI, or Pi
 * types are involved, so adapters can use this from any execution host.
 */
export class Guard {
  private readonly defaults: GuardOptions;
  private readonly cache = new Map<string, CacheEntry>();
  private cacheHits = 0;
  private cacheMisses = 0;

  constructor(options: GuardOptions = {}) {
    this.defaults = normalizeOptions(options);
  }

  clearCache(): void {
    this.cache.clear();
  }

  decide(input: GuardInput, options?: EvaluationOptions): Decision {
    const parsed = parseInput(input);
    if (isDecision(parsed)) return parsed;
    try {
      const effective = mergeOptions(this.defaults, { ...parsed.options, ...options });
      const key = cacheKey(parsed.command, effective);
      const now = Date.now();
      const cached = this.cache.get(key);
      if (cached && cached.expiresAt > now) {
        this.cache.delete(key);
        this.cache.set(key, cached);
        this.cacheHits += 1;
        return cached.decision;
      }
      if (cached) this.cache.delete(key);
      this.cacheMisses += 1;
      const result = evaluateCommand(parsed.command, effective);
      const decision = decisionFromResult(result);
      const max = effective.cacheMax ?? DEFAULT_CACHE_MAX;
      if (max > 0 && effective.cacheTtlMs !== 0 && (decision.action === "allow" || decision.action === "deny")) {
        this.cache.set(key, { decision, expiresAt: now + (effective.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS) });
        while (this.cache.size > max) this.cache.delete(this.cache.keys().next().value!);
      }
      return decision;
    } catch (error) {
      return evaluationError(error);
    }
  }

  /** Alias for callers that use evaluator terminology. */
  evaluate(input: GuardInput, options?: EvaluationOptions): Decision {
    return this.decide(input, options);
  }

  explain(input: GuardInput, options?: EvaluationOptions): Explanation {
    const parsed = parseInput(input);
    if (isDecision(parsed)) return explainError(input, parsed);
    try {
      const result = evaluateCommand(parsed.command, mergeOptions(this.defaults, { ...parsed.options, ...options }));
      return {
        ...decisionFromResult(result),
        command: parsed.command,
        normalized: result.normalized,
        matchedRules: [...result.matchedRules],
        highestSeverity: result.highestSeverity,
      };
    } catch (error) {
      return explainError(input, evaluationError(error));
    }
  }

  status(): GuardStatus {
    return {
      apiVersion: "1",
      engine: "native",
      implementation: "in-process",
      parser: "shell-lexer",
      ready: true,
      categories: [...(this.defaults.categories ?? ALL_CATEGORIES)],
      maxDepth: this.defaults.maxDepth ?? DEFAULT_MAX_DEPTH,
      capabilities: [...CAPABILITIES],
      diagnostics: [],
      cache: {
        entries: this.cache.size,
        hits: this.cacheHits,
        misses: this.cacheMisses,
        max: this.defaults.cacheMax ?? DEFAULT_CACHE_MAX,
        ttlMs: this.defaults.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS,
      },
    };
  }
}

/** Construct an independent guard instance with optional default policy. */
export function createGuard(options: GuardOptions = {}): Guard {
  return new Guard(options);
}

const defaultGuard = new Guard();

/** Evaluate one command at the default policy. */
export function decide(input: GuardInput, options?: EvaluationOptions): Decision {
  return defaultGuard.decide(input, options);
}

/** Alias for decide, useful when adapting an evaluator-shaped host API. */
export function evaluate(input: GuardInput, options?: EvaluationOptions): Decision {
  return defaultGuard.decide(input, options);
}

/** Explain one command, including normalized parser output and matched rules. */
export function explain(input: GuardInput, options?: EvaluationOptions): Explanation {
  return defaultGuard.explain(input, options);
}

/** Report implementation and configured policy status. */
export function status(options: GuardOptions = {}): GuardStatus {
  return new Guard(options).status();
}

export type { EvaluationContext, EvaluationOptions, EvaluationResult, RuleCategory, RuleFinding } from "./core/types.ts";
