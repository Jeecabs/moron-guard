import { parseShell, type ShellCommand } from "../shell-parser.ts";
import { evaluateCommandRules } from "./rules.ts";
import { SEVERITY_RANK, type EvaluationContext, type EvaluationOptions, type EvaluationResult, type FindingSeverity, type RuleCategory, type RuleFinding } from "./types.ts";

const MAX_COMMAND_BYTES = 128 * 1024;

function highestSeverity(findings: readonly RuleFinding[]): FindingSeverity | undefined {
  return findings.reduce<FindingSeverity | undefined>((highest, finding) => {
    if (!highest || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]) return finding.severity;
    return highest;
  }, undefined);
}

function matchesPattern(command: string, patterns: readonly string[]): boolean {
  return patterns.includes(command);
}

function allowedByPattern(command: ShellCommand, patterns: readonly string[]): boolean {
  return matchesPattern(command.command, patterns);
}

function categoryEnabled(category: RuleCategory, categories: readonly RuleCategory[] | undefined): boolean {
  return !categories || categories.includes(category);
}

function sourceFinding(command: string, ruleId: string, category: RuleCategory, message: string, remediation: string): RuleFinding {
  return {
    ruleId,
    category,
    severity: "critical",
    confidence: "high",
    message,
    remediation: { message: remediation },
    evidence: command.length > 240 ? `${command.slice(0, 237)}...` : command,
    location: { start: 0, end: command.length },
    command,
    origin: "top-level",
  };
}

function sourceLevelFindings(command: string): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const lower = command.toLowerCase();
  if (/\|\s*(?:sh|bash|zsh|dash)\b/.test(lower) && /(?:rm\s+-(?:[^\s]*r|[^\s]*f)|git\s+reset\s+--hard|drop\s+(?:table|database)|truncate\s+table)/i.test(command)) {
    findings.push(sourceFinding(command, "core.shell:piped-script", "system", "Untrusted script text is being piped directly into a shell.", "Save the script, inspect it, and run it only after review."));
  }
  if (/\beval\b/i.test(command) && /(?:rm\s+-|git\s+reset|drop\s+|truncate\s+)/i.test(command)) {
    findings.push(sourceFinding(command, "core.shell:eval", "system", "eval executes command text after normal parsing and can hide destructive operations.", "Avoid eval; use explicit argv and inspect the generated command."));
  }
  if (/(?:^|[;&|]\s*)(?:psql|mysql|mariadb|sqlite3|duckdb)\b[^\n]*<<[-]?\s*['"\\]?/i.test(command) && /\b(drop|truncate|delete\s+from)\b/i.test(command)) {
    findings.push(sourceFinding(command, "database.sql-heredoc", "database", "Database heredoc contains a destructive SQL statement.", "Review the SQL and add a restrictive predicate before execution."));
  }
  if (/(?:^|[;&|]\s*)python(?:3)?\b[^\n]*<<[-]?\s*['"\\]?/i.test(command) && /(?:rmtree|os\.(?:remove|unlink)|shutil\.|subprocess\.|system\s*\()/i.test(command)) {
    findings.push(sourceFinding(command, "core.system:python-heredoc", "system", "Python heredoc contains destructive filesystem or process operations.", "Review the script separately and replace destructive operations with a dry run."));
  }
  if (/^\s*git\s*\n\s*reset\s+--hard\b/i.test(command)) {
    findings.push(sourceFinding(command, "core.git:reset-hard", "git", "A line-separated reset --hard sequence can discard working-tree changes.", "Inspect the command sequence and stash changes before resetting."));
  }
  if (/\b(?:timeout|watch|strace|nohup|doas|exec|command|builtin)\b[\s\S]*\brm\s+-[\w-]*r[\w-]*\s+\//i.test(command)) {
    findings.push(sourceFinding(command, "core.filesystem:wrapped-remove", "filesystem", "A command wrapper hides a recursive removal operation.", "Inspect the wrapped command and narrow its target before execution."));
  }
  if (/\b(?:sh|bash|zsh|dash)\b\s+<<<\s*["']?[^\n]*(?:rm\s+-|git\s+reset\s+--hard)/i.test(command)) {
    findings.push(sourceFinding(command, "core.shell:here-string", "system", "A shell here-string contains a destructive command.", "Inspect the here-string contents before passing them to a shell."));
  }
  if (/\bcurl\b[\s\S]*\|\s*(?:sh|bash|zsh)\b/i.test(command)) {
    findings.push(sourceFinding(command, "core.shell:install-pipe", "system", "A remote response is being executed directly by a shell.", "Download the script, inspect it, and execute a pinned local copy."));
  }
  return findings;
}

export function evaluateCommand(command: string, options: EvaluationOptions = {}): EvaluationResult {
  const context: EvaluationContext = options.context ?? {};
  const maxCommandBytes = options.maxCommandBytes ?? MAX_COMMAND_BYTES;
  if (Buffer.byteLength(command, "utf8") > maxCommandBytes) {
    const finding = sourceFinding(command, "core.input:oversize", "system", "Command exceeds Moron Guard's bounded input size.", "Split the script into reviewed steps or use a sandboxed execution path.");
    return {
      deny: true,
      allowed: false,
      findings: [finding],
      matchedRules: [finding.ruleId],
      highestSeverity: finding.severity,
      warnings: [`command exceeds ${maxCommandBytes} UTF-8 bytes`],
      normalized: "<oversize command>",
    };
  }
  const parsedResult = parseShell(command, { maxDepth: options.maxDepth });
  const parsed = parsedResult.commands;
  const sourceAllowed = matchesPattern(command.trim(), options.allow ?? []);
  const dynamicWarnings = /\b(?:sh|bash|zsh|dash)\b[^\n;]*\s(?:-c|--command)\s+["']?\$(?:\{|[A-Za-z_])/i.test(command)
    ? ["opaque dynamic shell script"]
    : [];
  const findings: RuleFinding[] = sourceAllowed
    ? []
    : sourceLevelFindings(command).filter((finding) => categoryEnabled(finding.category, options.categories));

  for (const shellCommand of parsed) {
    if (allowedByPattern(shellCommand, options.allow ?? [])) continue;
    for (const finding of evaluateCommandRules(shellCommand, context)) {
      if (categoryEnabled(finding.category, options.categories)) findings.push(finding);
    }
  }

  const deduped = [...new Map(findings.map((finding) => [`${finding.ruleId}:${finding.location?.start}:${finding.location?.end}`, finding])).values()];
  const matchedRules = [...new Set(deduped.map((finding) => finding.ruleId))];
  return {
    deny: deduped.length > 0,
    allowed: deduped.length === 0,
    findings: deduped,
    matchedRules,
    highestSeverity: highestSeverity(deduped),
    warnings: [...new Set([...parsedResult.warnings, ...dynamicWarnings])],
    normalized: parsed.length > 0 ? parsed.map((entry) => entry.command).join(" && ") : command.trim(),
  };
}
