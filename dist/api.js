import { createHash } from "node:crypto";
import { redactDiagnosticText } from "./diagnostics.js";
import { evaluateCommand } from "./core/evaluate.js";
const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_CACHE_MAX = 2048;
const DEFAULT_CACHE_TTL_MS = 1000;
const ALL_CATEGORIES = [
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
const CAPABILITIES = ["decide", "explain", "status"];
function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
function validMaxDepth(value) {
    return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 32;
}
function validMaxCommandBytes(value) {
    return typeof value === "number" && Number.isInteger(value) && value >= 1024 && value <= 1024 * 1024;
}
function cloneContext(context) {
    if (!context)
        return undefined;
    return {
        ...context,
        env: context.env ? { ...context.env } : undefined,
    };
}
function normalizeOptions(options = {}) {
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
function mergeOptions(base, override) {
    if (!override)
        return normalizeOptions(base);
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
function findingDiagnostic(finding) {
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
function resultDiagnostics(result) {
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
function decisionFromResult(result) {
    const diagnostics = resultDiagnostics(result);
    if (!result.deny && result.warnings.length > 0)
        diagnostics.push(errorDiagnostic("guard.unknown-syntax", "Shell syntax could not be classified safely."));
    const action = result.deny ? "deny" : result.warnings.length > 0 ? "error" : "allow";
    return {
        action,
        enforce: action !== "allow",
        source: "native",
        diagnostics,
    };
}
function errorDiagnostic(code, message) {
    return { code, kind: "error", severity: "error", message };
}
function evaluationError(error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
        action: "error",
        enforce: true,
        source: "native",
        diagnostics: [errorDiagnostic("guard.evaluation-error", detail ? `Guard evaluation failed: ${redactDiagnosticText(detail)}` : "Guard evaluation failed.")],
    };
}
function parseInput(input) {
    if (typeof input === "string")
        return { command: input };
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
    return { command: input.command, options: input.options };
}
function isDecision(value) {
    return "action" in value;
}
function explainError(input, decision) {
    return {
        ...decision,
        command: typeof input === "string" ? input : isRecord(input) && typeof input.command === "string" ? input.command : "",
        normalized: "",
        matchedRules: [],
    };
}
function cacheKey(command, options) {
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
    defaults;
    cache = new Map();
    cacheHits = 0;
    cacheMisses = 0;
    constructor(options = {}) {
        this.defaults = normalizeOptions(options);
    }
    clearCache() {
        this.cache.clear();
    }
    decide(input, options) {
        const parsed = parseInput(input);
        if (isDecision(parsed))
            return parsed;
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
            if (cached)
                this.cache.delete(key);
            this.cacheMisses += 1;
            const result = evaluateCommand(parsed.command, effective);
            const decision = decisionFromResult(result);
            const max = effective.cacheMax ?? DEFAULT_CACHE_MAX;
            if (max > 0 && effective.cacheTtlMs !== 0 && (decision.action === "allow" || decision.action === "deny")) {
                this.cache.set(key, { decision, expiresAt: now + (effective.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS) });
                while (this.cache.size > max)
                    this.cache.delete(this.cache.keys().next().value);
            }
            return decision;
        }
        catch (error) {
            return evaluationError(error);
        }
    }
    /** Alias for callers that use evaluator terminology. */
    evaluate(input, options) {
        return this.decide(input, options);
    }
    explain(input, options) {
        const parsed = parseInput(input);
        if (isDecision(parsed))
            return explainError(input, parsed);
        try {
            const result = evaluateCommand(parsed.command, mergeOptions(this.defaults, { ...parsed.options, ...options }));
            return {
                ...decisionFromResult(result),
                command: parsed.command,
                normalized: result.normalized,
                matchedRules: [...result.matchedRules],
                highestSeverity: result.highestSeverity,
            };
        }
        catch (error) {
            return explainError(input, evaluationError(error));
        }
    }
    status() {
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
export function createGuard(options = {}) {
    return new Guard(options);
}
const defaultGuard = new Guard();
/** Evaluate one command at the default policy. */
export function decide(input, options) {
    return defaultGuard.decide(input, options);
}
/** Alias for decide, useful when adapting an evaluator-shaped host API. */
export function evaluate(input, options) {
    return defaultGuard.decide(input, options);
}
/** Explain one command, including normalized parser output and matched rules. */
export function explain(input, options) {
    return defaultGuard.explain(input, options);
}
/** Report implementation and configured policy status. */
export function status(options = {}) {
    return new Guard(options).status();
}
