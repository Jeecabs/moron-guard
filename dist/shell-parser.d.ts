/**
 * Small, dependency-free shell lexer/extractor.
 *
 * This is deliberately not a shell evaluator. It only deals with syntax that
 * is useful when inspecting a command before execution: words, quoting,
 * escaped newlines, command separators, shell -c wrappers, substitutions, and
 * heredocs. Expansion and execution are never performed.
 */
export type ShellCommandOrigin = "top-level" | "substitution" | "backtick" | "wrapper" | "heredoc";
export interface ShellCommand {
    /** Canonical representation of this command unit (without heredoc data). */
    command: string;
    /** First command word after assignment prefixes and redirections. */
    executable: string;
    /** Decoded command argv, excluding assignment prefixes and redirections. */
    argv: string[];
    /** Half-open source span. Wrapper scripts use the span of their -c argument. */
    start: number;
    end: number;
    origin: ShellCommandOrigin;
    /** Wrapper that caused a nested script to be inspected, when applicable. */
    wrapper?: string;
}
export interface ShellParseOptions {
    /** Maximum nesting depth for substitutions, wrappers, and heredocs. */
    maxDepth?: number;
}
export interface ShellParseResult {
    /** Top-level source normalized to safe, canonical shell words/operators. */
    normalized: string;
    /** Commands found at every shell execution level. */
    commands: ShellCommand[];
    /** Syntax/limit warnings; callers should fail closed when execution matters. */
    warnings: string[];
}
/** Parse shell syntax and return commands at all execution levels. */
export declare function parseShell(source: string, options?: ShellParseOptions): ShellParseResult;
/** Extract commands directly, convenient for guards that only need argv. */
export declare function extractShellCommands(source: string, options?: ShellParseOptions): ShellCommand[];
/** Canonicalize shell words/operators without executing expansion or data. */
export declare function normalizeShellCommand(source: string): string;
