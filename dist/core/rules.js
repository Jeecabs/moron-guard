import { extractShellCommands } from "../shell-parser.js";
const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish"]);
const EXEC_WRAPPERS = new Set(["command", "exec", "env", "doas", "nohup", "nice", "time", "timeout", "watch", "strace", "builtin", "xargs", "find"]);
const SAFE_TEMP_PREFIXES = ["/tmp/", "/private/tmp/", "/var/tmp/", "$TMPDIR/", "${TMPDIR}/", "%TEMP%\\"];
function basename(value) {
    const clean = value.replace(/^['"]|['"]$/g, "");
    const slash = Math.max(clean.lastIndexOf("/"), clean.lastIndexOf("\\"));
    return (slash >= 0 ? clean.slice(slash + 1) : clean).toLowerCase();
}
function hasFlag(args, long, short) {
    return args.some((arg) => arg === long || (short ? /^-[^-]+$/.test(arg) && arg.slice(1).includes(short) : false));
}
function hasValue(args, predicate) {
    return args.some((arg) => predicate(arg));
}
function operands(args) {
    const result = [];
    let options = true;
    for (const arg of args) {
        if (arg === "--") {
            options = false;
            continue;
        }
        if (options && arg.startsWith("-"))
            continue;
        result.push(arg);
    }
    return result;
}
function evidence(command) {
    return command.command.length > 240 ? `${command.command.slice(0, 237)}...` : command.command;
}
function finding(command, spec) {
    return {
        ...spec,
        confidence: spec.confidence ?? "high",
        evidence: spec.evidence ?? evidence(command),
        command: command.command,
        origin: command.origin,
        location: { start: command.start, end: command.end },
    };
}
function broadPath(path, context) {
    const normalized = path.replace(/^['"]|['"]$/g, "");
    if (SAFE_TEMP_PREFIXES.some((prefix) => normalized.startsWith(prefix)))
        return false;
    if (["/", "/*", ".", "./", "..", "../", "~", "~/*", "$HOME", "${HOME}"].includes(normalized))
        return true;
    if (context.cwd && (normalized === context.cwd || normalized === `${context.cwd}/`))
        return true;
    return false;
}
function allSafeTemp(paths) {
    return paths.length > 0 && paths.every((path) => SAFE_TEMP_PREFIXES.some((prefix) => path.startsWith(prefix)));
}
function gitArgs(args) {
    const result = [...args];
    while (result[0]?.startsWith("-")) {
        const option = result.shift();
        if (["-C", "-c", "--git-dir", "--work-tree", "--namespace"].includes(option))
            result.shift();
    }
    return result;
}
function sqlText(command) {
    const exe = basename(command.executable);
    if (!(exe === "psql" || exe === "mysql" || exe === "mariadb" || exe === "sqlite3" || exe === "duckdb"))
        return undefined;
    const args = command.argv.slice(1);
    const queryIndex = args.findIndex((arg) => arg === "-c" || arg === "--command" || arg === "-e" || arg === "--execute");
    return queryIndex >= 0 ? args[queryIndex + 1] : undefined;
}
function evaluateFilesystem(command, context) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (exe === "rm" && (hasFlag(args, "--recursive", "r") || hasFlag(args, "--recursive", "R") || hasFlag(args, "--dir", "d"))) {
        const paths = operands(args);
        if (!allSafeTemp(paths)) {
            const broad = paths.some((path) => broadPath(path, context));
            const dynamic = paths.some((path) => /[$*?{}]/.test(path));
            return [finding(command, {
                    ruleId: "core.filesystem:remove-recursive",
                    category: "filesystem",
                    confidence: dynamic && !broad ? "low" : "high",
                    severity: broad ? "critical" : "high",
                    message: broad ? "Recursive removal targets a broad or project-level path." : "Recursive removal can destroy a directory tree and uncommitted work.",
                    remediation: { message: "Inspect paths first; prefer a narrow, non-recursive removal or move files to a quarantine directory." },
                })];
        }
    }
    if (["shred", "srm", "unlink"].includes(exe)) {
        return [finding(command, {
                ruleId: `core.filesystem:${exe}-secure-delete`,
                category: "filesystem",
                severity: "high",
                message: "Secure deletion is intentionally difficult to recover from.",
                remediation: { message: "Use a reversible move/quarantine step first." },
            })];
    }
    return [];
}
function evaluateGit(command) {
    if (!["git", "git.exe"].includes(basename(command.executable)))
        return [];
    const args = gitArgs(command.argv.slice(1));
    const subcommand = args[0];
    if (subcommand === "reset" && hasFlag(args.slice(1), "--hard")) {
        return [finding(command, {
                ruleId: "core.git:reset-hard",
                category: "git",
                severity: "critical",
                message: "git reset --hard discards working-tree and index changes.",
                remediation: { message: "Create a stash or patch before resetting.", command: "git stash push -u" },
            })];
    }
    if (subcommand === "clean" && hasFlag(args.slice(1), "--force", "f")) {
        return [finding(command, {
                ruleId: "core.git:clean-force",
                category: "git",
                severity: hasFlag(args.slice(1), "-d", "d") || hasFlag(args.slice(1), "-x", "x") ? "critical" : "high",
                message: "git clean -f removes untracked files; -d/-x expands its reach.",
                remediation: { message: "Run git clean -n first, then remove only reviewed paths." },
            })];
    }
    if ((subcommand === "checkout" || subcommand === "restore") && (subcommand === "restore" && args.length > 1 || args.includes(".") || args.includes("--") || args.includes("-f"))) {
        return [finding(command, {
                ruleId: `core.git:${subcommand}-path`,
                category: "git",
                severity: "high",
                message: `git ${subcommand} overwrites tracked working-tree files.`,
                remediation: { message: "Inspect git diff and stash changes before restoring paths." },
            })];
    }
    if (subcommand === "stash" && ["drop", "clear"].includes(args[1] ?? "")) {
        return [finding(command, {
                ruleId: `core.git:stash-${args[1]}`,
                category: "git",
                severity: "critical",
                message: `git stash ${args[1]} permanently removes recoverable stashes.`,
                remediation: { message: "List and export stashes before deleting them." },
            })];
    }
    if (subcommand === "branch" && (hasFlag(args.slice(1), "--delete", "D") || args.includes("--delete"))) {
        return [finding(command, {
                ruleId: "core.git:branch-force-delete",
                category: "git",
                severity: "high",
                message: "Force-deleting a branch can discard commits that are not reachable elsewhere.",
                remediation: { message: "Verify the branch is merged and record its tip before deletion." },
            })];
    }
    if (subcommand === "push" && (hasFlag(args.slice(1), "--force", "f") || args.some((arg) => arg === "--force-with-lease" || arg.startsWith("--force=")) || args.includes("--delete"))) {
        return [finding(command, {
                ruleId: "core.git:push-destructive",
                category: "git",
                severity: "critical",
                message: "Force push or remote branch deletion rewrites shared history.",
                remediation: { message: "Use a protected branch and --force-with-lease only after reviewing the remote diff." },
            })];
    }
    if (subcommand === "filter-branch" || subcommand === "filter-repo" || subcommand === "reflog" && args.includes("expire") || subcommand === "gc" && hasValue(args, (arg) => arg.includes("prune"))) {
        return [finding(command, {
                ruleId: "core.git:recovery-expiration",
                category: "git",
                severity: "high",
                message: "This Git maintenance command can remove recovery data.",
                remediation: { message: "Keep reflogs and unreachable objects until backups are verified." },
            })];
    }
    return [];
}
function evaluateSystem(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (exe === "dd" && hasValue(args, (arg) => /^(of|if)=\/dev\//i.test(arg))) {
        return [finding(command, {
                ruleId: "core.system:dd-device",
                category: "system",
                severity: "critical",
                message: "dd is targeting a block device and can destroy a disk without recovery.",
                remediation: { message: "Confirm device identity, unmount it, and create a verified image first." },
            })];
    }
    if (["mkfs", "mkfs.ext4", "mkfs.xfs", "wipefs", "fdisk", "parted", "diskpart"].includes(exe)) {
        return [finding(command, {
                ruleId: `core.system:${exe}`,
                category: "system",
                severity: "critical",
                message: `${exe} modifies or destroys filesystem/device metadata.`,
                remediation: { message: "Use a disposable device and verify the target explicitly before proceeding." },
            })];
    }
    if (exe === "dropdb" || exe === "dropdatabase") {
        return [finding(command, {
                ruleId: "database.drop-database",
                category: "database",
                severity: "critical",
                message: "Database drop command destroys an entire database.",
                remediation: { message: "Verify backups and target identity before any database removal." },
            })];
    }
    if (exe === "diskutil" && ["eraseDisk", "eraseVolume", "partitionDisk"].includes(args[0] ?? "")) {
        return [finding(command, {
                ruleId: "core.system:diskutil-erase",
                category: "system",
                severity: "critical",
                message: "diskutil erase operation destroys a volume or partition.",
                remediation: { message: "Verify the disk identifier and take a current backup first." },
            })];
    }
    return [];
}
function evaluatePermissions(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if ((exe === "chmod" || exe === "chown") && (hasFlag(args, "--recursive", "R") || hasValue(args, (arg) => arg.includes("777")))) {
        return [finding(command, {
                ruleId: `core.permissions:${exe}-broad`,
                category: "permissions",
                severity: "high",
                message: `${exe} applies a broad recursive or world-writable permission change.`,
                remediation: { message: "Target a specific file and use the narrowest permission change possible." },
            })];
    }
    return [];
}
function evaluateDatabase(command) {
    const text = sqlText(command);
    if (!text)
        return [];
    const normalized = text.replace(/\/\*[^]*?\*\//g, " ").replace(/--[^\n]*/g, " ").toUpperCase();
    let ruleId;
    let message;
    if (/\bDROP\s+(DATABASE|SCHEMA|TABLE|INDEX|VIEW|FUNCTION)\b/.test(normalized)) {
        ruleId = "database.sql-drop";
        message = "SQL DROP destroys database objects.";
    }
    else if (/\bTRUNCATE\b/.test(normalized)) {
        ruleId = "database.sql-truncate";
        message = "TRUNCATE removes table contents without row-level recovery.";
    }
    else if (/\b(DELETE|UPDATE)\b[\s\S]*\bFROM\b|\bDELETE\s+FROM\b/.test(normalized) && !/\bWHERE\b/.test(normalized)) {
        ruleId = "database.sql-unbounded-mutation";
        message = "SQL mutation has no WHERE clause and may affect every row.";
    }
    return ruleId && message ? [finding(command, {
            ruleId,
            category: "database",
            severity: "critical",
            message,
            remediation: { message: "Run a SELECT with the same predicate, add a restrictive WHERE, and verify a backup." },
            evidence: text,
        })] : [];
}
function evaluatePackageManager(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (["npm", "pnpm", "yarn", "bun"].includes(exe) && args[0] === "cache" && args[1] === "clean" && hasFlag(args.slice(2), "--force", "f")) {
        return [finding(command, {
                ruleId: "package-manager.cache-clean-force",
                category: "package-manager",
                severity: "medium",
                message: "Forced package-cache cleanup removes local recovery/debug data.",
                remediation: { message: "Inspect cache usage first; avoid force unless disk pressure is confirmed." },
            })];
    }
    if (exe === "pnpm" && args[0] === "store" && args[1] === "prune") {
        return [finding(command, {
                ruleId: "package-manager.pnpm-store-prune",
                category: "package-manager",
                severity: "medium",
                message: "pnpm store prune removes packages that may be needed for offline recovery.",
                remediation: { message: "Verify no active workspace depends on the store entries first." },
            })];
    }
    if (exe === "npm" && ["unpublish", "deprecate"].includes(args[0] ?? "")) {
        return [finding(command, {
                ruleId: `package-manager.npm-${args[0]}`,
                category: "package-manager",
                severity: "high",
                message: `npm ${args[0]} changes or removes published package state for other users.`,
                remediation: { message: "Use a reviewed release/deprecation workflow with an explicit package and version." },
            })];
    }
    return [];
}
function evaluateContainers(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (exe === "docker" && args[0] === "system" && args[1] === "prune" && hasFlag(args.slice(2), "--force", "f")) {
        return [finding(command, {
                ruleId: "containers.docker-system-prune",
                category: "containers",
                severity: "high",
                message: "Docker system prune removes unused images, containers, networks, and possibly volumes.",
                remediation: { message: "Preview with docker system df and prune selected resources explicitly." },
            })];
    }
    if (exe === "docker" && args[0] === "compose" && args.includes("down") && hasFlag(args, "--volumes", "v")) {
        return [finding(command, {
                ruleId: "containers.compose-down-volumes",
                category: "containers",
                severity: "high",
                message: "docker compose down --volumes destroys persistent service data.",
                remediation: { message: "Stop services without removing volumes, or back up volumes first." },
            })];
    }
    if (exe === "docker" && args[0] === "volume" && ["prune", "rm"].includes(args[1] ?? "")) {
        return [finding(command, {
                ruleId: "containers.docker-volume-delete",
                category: "containers",
                severity: "high",
                message: "Docker volume deletion can destroy persistent application data.",
                remediation: { message: "List volume consumers and back up data before deleting a volume." },
            })];
    }
    if (exe === "kubectl" && args[0] === "delete" && (args.includes("namespace") || args.includes("namespaces") || args.includes("--all"))) {
        return [finding(command, {
                ruleId: "kubernetes.kubectl-delete-broad",
                category: "kubernetes",
                severity: "critical",
                message: "kubectl delete targets a namespace or all matching resources.",
                remediation: { message: "Use kubectl get first and delete a named resource with an explicit namespace." },
            })];
    }
    return [];
}
function evaluateCloudRemote(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (exe === "rsync" && hasValue(args, (arg) => arg === "--delete" || arg.startsWith("--delete-"))) {
        return [finding(command, {
                ruleId: "remote.rsync-delete",
                category: "remote",
                severity: "high",
                message: "rsync --delete removes destination files absent from the source.",
                remediation: { message: "Run without --delete or use --dry-run and review the deletion list." },
            })];
    }
    if (exe === "aws" && args.includes("s3") && args.includes("rm") && hasFlag(args, "--recursive")) {
        return [finding(command, {
                ruleId: "cloud.aws-s3-recursive-delete",
                category: "cloud",
                severity: "critical",
                message: "Recursive S3 deletion can remove an entire bucket prefix.",
                remediation: { message: "Use --dryrun and a narrowly scoped prefix; verify account and region." },
            })];
    }
    if (exe === "aws" && ((args[0] === "ec2" && args.includes("terminate-instances")) || (args[0] === "rds" && args.includes("delete-db-instance")))) {
        return [finding(command, {
                ruleId: "cloud.aws-resource-delete",
                category: "cloud",
                severity: "critical",
                message: "AWS command terminates or deletes a cloud resource.",
                remediation: { message: "Verify account, region, resource identity, and backup before deletion." },
            })];
    }
    if ((exe === "gcloud" && args.includes("delete")) || (exe === "az" && args.includes("delete") && args.includes("--yes"))) {
        return [finding(command, {
                ruleId: "cloud.provider-resource-delete",
                category: "cloud",
                severity: "critical",
                message: "Cloud CLI delete operation can remove remote infrastructure.",
                remediation: { message: "Use a dry-run/plan where available and verify the active account and target." },
            })];
    }
    return [];
}
function synthetic(command, executable, argv, origin = "wrapper") {
    return { ...command, command: argv.join(" "), executable, argv, origin };
}
function evaluateWrapper(command, context) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    if (!EXEC_WRAPPERS.has(exe))
        return [];
    if (exe === "find" && (args.includes("-delete") || args.includes("-exec") || args.includes("-execdir"))) {
        const index = args.findIndex((arg) => arg === "-exec" || arg === "-execdir");
        const target = index >= 0 ? args[index + 1] : undefined;
        if (target && basename(target) === "rm") {
            return evaluateCommandRules(synthetic(command, target, args.slice(index + 1)), context);
        }
        if (args.includes("-delete"))
            return [finding(command, {
                    ruleId: "core.filesystem:find-delete",
                    category: "filesystem",
                    severity: "high",
                    message: "find -delete removes every matched path without a review step.",
                    remediation: { message: "Use find without -delete, review the result, then remove explicit paths." },
                })];
    }
    let index = 0;
    while (index < args.length) {
        const value = args[index];
        if (exe === "timeout" && (/^\d/.test(value) || value.endsWith("s") || value.endsWith("m"))) {
            index += 1;
            continue;
        }
        if (exe === "nice" && (value === "-n" || value === "--adjustment")) {
            index += 2;
            continue;
        }
        if (value.startsWith("-") || (exe === "env" && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(value) || value === "-i"))) {
            index += 1;
            continue;
        }
        break;
    }
    const target = args[index];
    if (!target)
        return [];
    const inner = synthetic(command, target, args.slice(index));
    if (SHELLS.has(basename(target))) {
        const innerArgs = inner.argv.slice(1);
        const scriptIndex = innerArgs.findIndex((arg) => arg === "-c" || arg === "--command");
        const script = scriptIndex >= 0 ? innerArgs[scriptIndex + 1] : undefined;
        if (script)
            return extractShellCommands(script).flatMap((nested) => evaluateCommandRules(nested, context));
    }
    return evaluateCommandRules(inner, context);
}
function evaluateInlineInterpreter(command) {
    const exe = basename(command.executable);
    const args = command.argv.slice(1);
    const flagIndex = args.findIndex((arg) => ["-c", "-e", "--command", "--eval"].includes(arg));
    const script = flagIndex >= 0 ? args[flagIndex + 1] : undefined;
    const destructiveScript = typeof script === "string" && /(rmtree|rm_rf|child_process|execSync|system|os\.(remove|unlink)|FileUtils\.rm_rf)/i.test(script);
    if (["python", "python3", "node", "ruby", "perl"].includes(exe) && destructiveScript) {
        return [finding(command, {
                ruleId: `core.system:inline-${exe}`,
                category: "system",
                severity: "critical",
                message: `${exe} inline script contains a destructive process or filesystem operation.`,
                remediation: { message: "Review the script separately and replace destructive operations with a dry run." },
                evidence: script,
            })];
    }
    if (exe === "systemctl" && ["stop", "disable", "mask"].includes(command.argv[1] ?? "")) {
        return [finding(command, {
                ruleId: "core.system:service-stop",
                category: "system",
                severity: "high",
                message: "Stopping or disabling a system service can interrupt the host or security controls.",
                remediation: { message: "Inspect service dependencies and use a reversible user-level test service." },
            })];
    }
    if ((exe === "echo" || exe === "printf" || exe === "cat") && />\s*\/dev\//.test(command.command)) {
        return [finding(command, {
                ruleId: "core.system:redirect-device",
                category: "system",
                severity: "critical",
                message: "Shell redirection targets a block device.",
                remediation: { message: "Verify the destination is not a device before writing." },
            })];
    }
    return [];
}
export function evaluateCommandRules(command, context) {
    const findings = [
        ...evaluateFilesystem(command, context),
        ...evaluateGit(command),
        ...evaluateSystem(command),
        ...evaluatePermissions(command),
        ...evaluateDatabase(command),
        ...evaluateContainers(command),
        ...evaluateCloudRemote(command),
        ...evaluatePackageManager(command),
        ...evaluateWrapper(command, context),
        ...evaluateInlineInterpreter(command),
    ];
    return findings;
}
