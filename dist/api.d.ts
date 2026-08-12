import type { EvaluationOptions, FindingConfidence, FindingLocation, FindingSeverity, Remediation, RuleCategory } from "./core/types.ts";
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
    cache?: {
        entries: number;
        hits: number;
        misses: number;
        max: number;
        ttlMs: number;
    };
}
/**
 * Reusable, host-independent Moron Guard API.
 *
 * It only calls the in-process native evaluator. No host lifecycle, UI, or Pi
 * types are involved, so adapters can use this from any execution host.
 */
export declare class Guard {
    private readonly defaults;
    private readonly cache;
    private cacheHits;
    private cacheMisses;
    constructor(options?: GuardOptions);
    clearCache(): void;
    decide(input: GuardInput, options?: EvaluationOptions): Decision;
    /** Alias for callers that use evaluator terminology. */
    evaluate(input: GuardInput, options?: EvaluationOptions): Decision;
    explain(input: GuardInput, options?: EvaluationOptions): Explanation;
    status(): GuardStatus;
}
/** Construct an independent guard instance with optional default policy. */
export declare function createGuard(options?: GuardOptions): Guard;
/** Evaluate one command at the default policy. */
export declare function decide(input: GuardInput, options?: EvaluationOptions): Decision;
/** Alias for decide, useful when adapting an evaluator-shaped host API. */
export declare function evaluate(input: GuardInput, options?: EvaluationOptions): Decision;
/** Explain one command, including normalized parser output and matched rules. */
export declare function explain(input: GuardInput, options?: EvaluationOptions): Explanation;
/** Report implementation and configured policy status. */
export declare function status(options?: GuardOptions): GuardStatus;
export type { EvaluationContext, EvaluationOptions, EvaluationResult, RuleCategory, RuleFinding } from "./core/types.ts";
