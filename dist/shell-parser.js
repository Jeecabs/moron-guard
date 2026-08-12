/**
 * Small, dependency-free shell lexer/extractor.
 *
 * This is deliberately not a shell evaluator. It only deals with syntax that
 * is useful when inspecting a command before execution: words, quoting,
 * escaped newlines, command separators, shell -c wrappers, substitutions, and
 * heredocs. Expansion and execution are never performed.
 */
const DEFAULT_MAX_DEPTH = 8;
// Longest first. Redirections are operators, but do not terminate a command.
const OPERATORS = [
    ";;&", "&>>", "<<<", "<<-", ">>", "<<", "&&", "||", "|&", ";;", ";|",
    ">&", "<&", "&>", ">|", ";", "&", "|", "(", ")", "{", "}", ">", "<", "\n",
];
const COMMAND_BOUNDARIES = new Set([";", ";;", ";;&", ";|", "&&", "||", "|", "|&", "&", "\n", "(", ")", "{", "}"]);
const REDIRECTIONS = new Set([">", ">>", "<", "<>", ">&", "<&", "&>", "&>>", ">|", "<<", "<<-", "<<<"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const CONTROL_WORDS = new Set([
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac", "in",
    "select", "function", "time", "!",
]);
const SHELL_NAMES = new Set(["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish"]);
function operatorAt(source, position, end) {
    for (const operator of OPERATORS) {
        if (position + operator.length <= end && source.startsWith(operator, position))
            return operator;
    }
    return undefined;
}
function isWhitespace(character) {
    return character === " " || character === "\t" || character === "\r" || character === "\f" || character === "\v";
}
function consumeBacktick(source, start, end) {
    let position = start + 1;
    while (position < end) {
        const character = source[position];
        if (character === "\\") {
            position += Math.min(2, end - position);
            continue;
        }
        if (character === "`")
            return { close: position, innerStart: start + 1, innerEnd: position };
        position += 1;
    }
    return undefined;
}
/** Find the closing parenthesis for a $(...) expression. */
function consumeCommandSubstitution(source, start, end) {
    let position = start + 2;
    let depth = 1;
    let quote;
    while (position < end) {
        const character = source[position];
        if (character === "\\") {
            position += Math.min(2, end - position);
            continue;
        }
        if (quote) {
            if (character === quote)
                quote = undefined;
            position += 1;
            continue;
        }
        if (character === "'" || character === '"') {
            quote = character;
            position += 1;
            continue;
        }
        if (character === "`") {
            const nested = consumeBacktick(source, position, end);
            position = nested ? nested.close + 1 : end;
            continue;
        }
        if (source.startsWith("$(", position)) {
            depth += 1;
            position += 2;
            continue;
        }
        if (character === "(") {
            depth += 1;
            position += 1;
            continue;
        }
        if (character === ")") {
            depth -= 1;
            if (depth === 0)
                return { close: position, innerStart: start + 2, innerEnd: position };
            position += 1;
            continue;
        }
        position += 1;
    }
    return undefined;
}
/** Consume ${...} as one shell word; braces inside it are not command separators. */
function consumeParameterExpansion(source, start, end) {
    let position = start + 2;
    let depth = 1;
    let quote;
    while (position < end) {
        const character = source[position];
        if (character === "\\") {
            position += Math.min(2, end - position);
            continue;
        }
        if (quote) {
            if (character === quote)
                quote = undefined;
            position += 1;
            continue;
        }
        if (character === "'" || character === '"') {
            quote = character;
            position += 1;
            continue;
        }
        if (source.startsWith("${", position)) {
            depth += 1;
            position += 2;
            continue;
        }
        if (character === "{") {
            depth += 1;
            position += 1;
            continue;
        }
        if (character === "}") {
            depth -= 1;
            if (depth === 0)
                return position + 1;
        }
        position += 1;
    }
    return undefined;
}
/** Arithmetic expansion uses $(()) syntax but does not execute shell commands. */
function consumeArithmeticExpansion(source, start, end) {
    const nested = consumeCommandSubstitution(source, start, end);
    return nested ? nested.close + 1 : undefined;
}
function decodeWord(raw) {
    let value = "";
    let position = 0;
    while (position < raw.length) {
        const character = raw[position];
        if (character === "'") {
            const close = raw.indexOf("'", position + 1);
            if (close < 0) {
                value += raw.slice(position + 1);
                break;
            }
            value += raw.slice(position + 1, close);
            position = close + 1;
            continue;
        }
        if (character === '"') {
            position += 1;
            while (position < raw.length) {
                const inner = raw[position];
                if (inner === '"') {
                    position += 1;
                    break;
                }
                if (inner === "\\" && position + 1 < raw.length) {
                    const escaped = raw[position + 1];
                    if (escaped === "\n") {
                        position += 2;
                    }
                    else if ("$`\\\"\n".includes(escaped)) {
                        value += escaped;
                        position += 2;
                    }
                    else {
                        value += "\\" + escaped;
                        position += 2;
                    }
                    continue;
                }
                value += inner;
                position += 1;
            }
            continue;
        }
        if (character === "\\" && position + 1 < raw.length) {
            if (raw[position + 1] !== "\n")
                value += raw[position + 1];
            position += 2;
            continue;
        }
        value += character;
        position += 1;
    }
    return value;
}
function unclosedQuote(raw) {
    let quote;
    let escaped = false;
    for (const character of raw) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (character === "\\" && quote !== "'") {
            escaped = true;
            continue;
        }
        if (quote) {
            if (character === quote)
                quote = undefined;
            continue;
        }
        if (character === "'" || character === '"')
            quote = character;
    }
    return quote;
}
function wordToken(source, start, end) {
    const raw = source.slice(start, end);
    let quoted = false;
    const embedded = [];
    let position = start;
    let quote;
    while (position < end) {
        const character = source[position];
        if (quote === "'") {
            if (character === "'")
                quote = undefined;
            position += 1;
            continue;
        }
        if (quote === '"') {
            if (character === '"') {
                quote = undefined;
                position += 1;
                continue;
            }
            if (character === "\\") {
                quoted = true;
                position += Math.min(2, end - position);
                continue;
            }
            if (source.startsWith("$(", position)) {
                if (source.startsWith("$((", position)) {
                    const arithmeticEnd = consumeArithmeticExpansion(source, position, end);
                    if (arithmeticEnd !== undefined) {
                        position = arithmeticEnd;
                        continue;
                    }
                }
                const nested = consumeCommandSubstitution(source, position, end);
                if (nested) {
                    embedded.push({ kind: "substitution", start: nested.innerStart, end: nested.innerEnd });
                    position = nested.close + 1;
                    continue;
                }
            }
            if (character === "`") {
                const nested = consumeBacktick(source, position, end);
                if (nested) {
                    embedded.push({ kind: "backtick", start: nested.innerStart, end: nested.innerEnd });
                    position = nested.close + 1;
                    continue;
                }
            }
            position += 1;
            continue;
        }
        if (character === "'") {
            quoted = true;
            quote = "'";
            position += 1;
            continue;
        }
        if (character === '"') {
            quoted = true;
            quote = '"';
            position += 1;
            continue;
        }
        if (character === "\\") {
            quoted = true;
            position += Math.min(2, end - position);
            continue;
        }
        if (source.startsWith("$(", position)) {
            if (source.startsWith("$((", position)) {
                const arithmeticEnd = consumeArithmeticExpansion(source, position, end);
                if (arithmeticEnd !== undefined) {
                    position = arithmeticEnd;
                    continue;
                }
            }
            const nested = consumeCommandSubstitution(source, position, end);
            if (nested) {
                embedded.push({ kind: "substitution", start: nested.innerStart, end: nested.innerEnd });
                position = nested.close + 1;
                continue;
            }
        }
        if (character === "`") {
            const nested = consumeBacktick(source, position, end);
            if (nested) {
                embedded.push({ kind: "backtick", start: nested.innerStart, end: nested.innerEnd });
                position = nested.close + 1;
                continue;
            }
        }
        position += 1;
    }
    return { kind: "word", raw, value: decodeWord(raw), start, end, quoted, embedded };
}
function findHeredocTerminator(source, bodyStart, end, delimiter, stripTabs) {
    let lineStart = bodyStart;
    while (lineStart <= end) {
        const newline = source.indexOf("\n", lineStart);
        const lineEnd = newline < 0 || newline >= end ? end : newline;
        let line = source.slice(lineStart, lineEnd);
        if (line.endsWith("\r"))
            line = line.slice(0, -1);
        if (stripTabs)
            line = line.replace(/^\t+/, "");
        if (line === delimiter)
            return { bodyEnd: lineStart, lineEnd };
        if (lineEnd >= end)
            break;
        lineStart = lineEnd + 1;
    }
    return { bodyEnd: end, lineEnd: end };
}
function scanShell(source, start, end) {
    const tokens = [];
    const heredocs = [];
    const warnings = [];
    const pending = [];
    let awaitingDelimiter;
    let position = start;
    const consumePendingHeredocs = (newlineEnd) => {
        let cursor = newlineEnd;
        while (pending.length > 0 && cursor <= end) {
            const item = pending.shift();
            if (!item.delimiter)
                continue;
            const found = findHeredocTerminator(source, cursor, end, item.delimiter.value ?? "", item.stripTabs);
            heredocs.push({
                delimiter: item.delimiter.value ?? "",
                bodyStart: cursor,
                bodyEnd: found.bodyEnd,
                operatorStart: item.operator.start,
                quoted: Boolean(item.delimiter.quoted),
                stripTabs: item.stripTabs,
            });
            cursor = found.lineEnd;
            // Multiple heredocs are consumed one after another. Leave the final
            // terminator newline for the regular lexer so it remains a separator.
            if (pending.length > 0 && cursor < end && source[cursor] === "\n")
                cursor += 1;
            if (found.bodyEnd === end)
                break;
        }
        return cursor;
    };
    while (position < end) {
        const character = source[position];
        if (character === "\\" && source[position + 1] === "\n") {
            position += 2;
            continue;
        }
        if (isWhitespace(character)) {
            position += 1;
            continue;
        }
        if (character === "#") {
            // The scanner only reaches this point between words, so # starts a
            // comment. A # encountered inside wordToken is ordinary data.
            while (position < end && source[position] !== "\n")
                position += 1;
            continue;
        }
        if (character === "\n") {
            const token = { kind: "operator", raw: "\n", operator: "\n", start: position, end: position + 1 };
            tokens.push(token);
            position = consumePendingHeredocs(position + 1);
            awaitingDelimiter = undefined;
            continue;
        }
        const operator = operatorAt(source, position, end);
        if (operator) {
            const token = { kind: "operator", raw: operator, operator, start: position, end: position + operator.length };
            tokens.push(token);
            position += operator.length;
            if (awaitingDelimiter)
                awaitingDelimiter = undefined;
            if (operator === "<<" || operator === "<<-") {
                awaitingDelimiter = { operator: token, stripTabs: operator === "<<-" };
            }
            continue;
        }
        const tokenStart = position;
        // A word ends only at shell whitespace or an operator. Quotes and nested
        // substitutions are consumed as part of the word.
        while (position < end) {
            const inner = source[position];
            if (inner === "\\" && source[position + 1] === "\n") {
                position += 2;
                continue;
            }
            if (isWhitespace(inner) || inner === "\n" || operatorAt(source, position, end))
                break;
            if (inner === "#" && position === tokenStart)
                break;
            if (inner === "'") {
                position += 1;
                while (position < end) {
                    if (source[position] === "\\" && source[position + 1] === "\n") {
                        position += 2;
                    }
                    else if (source[position] === "'") {
                        position += 1;
                        break;
                    }
                    else {
                        position += 1;
                    }
                }
                continue;
            }
            if (inner === '"') {
                position += 1;
                while (position < end) {
                    if (source[position] === "\\" && position + 1 < end) {
                        position += Math.min(2, end - position);
                    }
                    else if (source[position] === '"') {
                        position += 1;
                        break;
                    }
                    else {
                        position += 1;
                    }
                }
                continue;
            }
            if (inner === "\\") {
                position += Math.min(2, end - position);
                continue;
            }
            if (source.startsWith("${", position)) {
                const parameterEnd = consumeParameterExpansion(source, position, end);
                if (parameterEnd !== undefined) {
                    position = parameterEnd;
                    continue;
                }
            }
            if (source.startsWith("$(", position)) {
                if (source.startsWith("$((", position)) {
                    const arithmeticEnd = consumeArithmeticExpansion(source, position, end);
                    if (arithmeticEnd !== undefined) {
                        position = arithmeticEnd;
                        continue;
                    }
                }
                const nested = consumeCommandSubstitution(source, position, end);
                if (nested) {
                    position = nested.close + 1;
                    continue;
                }
            }
            if (inner === "`") {
                const nested = consumeBacktick(source, position, end);
                if (nested) {
                    position = nested.close + 1;
                    continue;
                }
            }
            position += 1;
        }
        // A leading # was handled above; malformed input can still leave us here.
        if (position === tokenStart) {
            position += 1;
            continue;
        }
        const token = wordToken(source, tokenStart, position);
        const quote = unclosedQuote(token.raw);
        if (quote)
            warnings.push(`unclosed ${quote} quote at byte ${token.start}`);
        tokens.push(token);
        if (awaitingDelimiter) {
            pending.push({ delimiter: token, operator: awaitingDelimiter.operator, stripTabs: awaitingDelimiter.stripTabs });
            awaitingDelimiter = undefined;
        }
    }
    return { tokens, heredocs, warnings };
}
function splitSegments(scan) {
    const segments = [];
    let tokens = [];
    const flush = () => {
        if (tokens.some((token) => token.kind === "word"))
            segments.push({ tokens, heredocs: [] });
        tokens = [];
    };
    for (const token of scan.tokens) {
        if (token.kind === "operator" && COMMAND_BOUNDARIES.has(token.operator ?? "")) {
            flush();
        }
        else {
            tokens.push(token);
        }
    }
    flush();
    for (const heredoc of scan.heredocs) {
        // The heredoc operator is part of exactly one command segment.
        const segment = segments.find((candidate) => candidate.tokens.some((token) => token.start === heredoc.operatorStart));
        segment?.heredocs.push(heredoc);
    }
    return segments;
}
function commandEntries(tokens) {
    const all = [];
    const words = [];
    let skipNext = false;
    for (let index = 0; index < tokens.length; index += 1) {
        const token = tokens[index];
        if (token.kind === "operator" && REDIRECTIONS.has(token.operator ?? "")) {
            all.push(token);
            skipNext = true;
            continue;
        }
        if (token.kind === "word") {
            // A numeric fd immediately adjacent to a redirection is syntax, not argv.
            const next = tokens[index + 1];
            if (/^\d+$/.test(token.value ?? "") && next?.kind === "operator" && REDIRECTIONS.has(next.operator ?? "") && token.end === next.start) {
                all.push(token);
                continue;
            }
            const previous = tokens[index - 1];
            if (previous?.kind === "operator" && REDIRECTIONS.has(previous.operator ?? "") && skipNext) {
                skipNext = false;
                all.push(token);
                continue;
            }
            if (skipNext) {
                skipNext = false;
                all.push(token);
                continue;
            }
            words.push({ token, value: token.value ?? "" });
            all.push(token);
            continue;
        }
        all.push(token);
    }
    let firstCommand = 0;
    const assignments = [];
    while (firstCommand < words.length && ASSIGNMENT.test(words[firstCommand].value)) {
        assignments.push(words[firstCommand].value);
        firstCommand += 1;
    }
    while (firstCommand < words.length && CONTROL_WORDS.has(words[firstCommand].value))
        firstCommand += 1;
    // `2>file` is lexed as the word 2 followed by > and file. Remove the fd
    // word from argv when it is adjacent to the redirection operator.
    const commandWords = words.filter((entry, index) => {
        if (index >= firstCommand)
            return true;
        return false;
    });
    return { all, command: commandWords, assignments };
}
function shellQuote(value) {
    if (value.length > 0 && /^[A-Za-z0-9_@%+=:,./-]+$/.test(value))
        return value;
    return `'${value.replaceAll("'", "'\\''")}'`;
}
function canonicalTokens(tokens) {
    let output = "";
    for (const token of tokens) {
        const text = token.kind === "operator" ? token.operator ?? token.raw : shellQuote(token.value ?? "");
        if (token.kind === "operator" && [">", ">>", "<", "<>", ">&", "<&", "&>", "&>>", ">|", "<<", "<<-", "<<<"].includes(token.operator ?? "")) {
            output += output.length > 0 && !output.endsWith(" ") ? " " : "";
            output += text;
            output += " ";
        }
        else if (token.kind === "operator" && token.operator !== "\n") {
            output += output.length > 0 && !output.endsWith(" ") ? " " : "";
            output += text;
            output += " ";
        }
        else if (token.kind === "operator") {
            output = output.trimEnd() + "\n";
        }
        else {
            output += output.length > 0 && !output.endsWith(" ") && !output.endsWith("\n") ? " " : "";
            output += text;
        }
    }
    return output.trim();
}
function basename(executable) {
    const slash = executable.lastIndexOf("/");
    return (slash >= 0 ? executable.slice(slash + 1) : executable).toLowerCase();
}
function isShell(executable) {
    const name = basename(executable);
    return SHELL_NAMES.has(name) || (name === "busybox");
}
function skipEnvOptions(values, index) {
    while (index < values.length) {
        const value = values[index];
        if (ASSIGNMENT.test(value)) {
            index += 1;
        }
        else if (value === "--") {
            return index + 1;
        }
        else if (value === "-u" || value === "--unset" || value === "-C" || value === "--chdir") {
            index += 2;
        }
        else if (value.startsWith("--unset=") || value.startsWith("--chdir=")) {
            index += 1;
        }
        else if (value.startsWith("-") && value !== "-") {
            index += 1;
        }
        else {
            break;
        }
    }
    return index;
}
function skipSudoOptions(values, index) {
    while (index < values.length) {
        const value = values[index];
        if (value === "--")
            return index + 1;
        if (!value.startsWith("-"))
            break;
        if (value === "-u" || value === "-g" || value === "-h" || value === "-C" || value === "--user" || value === "--group" || value === "--chdir")
            index += 2;
        else
            index += 1;
    }
    return index;
}
function findWrappedCommand(values) {
    let index = 0;
    const wrappers = [];
    while (index < values.length) {
        const name = basename(values[index]);
        if (name === "env") {
            wrappers.push(values[index]);
            index = skipEnvOptions(values, index + 1);
            continue;
        }
        if (name === "sudo") {
            wrappers.push(values[index]);
            index = skipSudoOptions(values, index + 1);
            continue;
        }
        if (index >= values.length)
            return undefined;
        return { index, wrapper: wrappers.join(" ") };
    }
    return undefined;
}
function findShellIndex(values) {
    const found = findWrappedCommand(values);
    if (!found || !isShell(values[found.index]))
        return undefined;
    let index = found.index;
    const wrappers = found.wrapper ? [found.wrapper] : [];
    if (basename(values[index]) === "busybox") {
        if (!values[index + 1] || !isShell(values[index + 1]))
            return undefined;
        index += 1;
    }
    wrappers.push(values[index]);
    return { index, wrapper: wrappers.join(" ") };
}
function findShellScriptArgument(entries) {
    if (entries.length === 0)
        return undefined;
    const values = entries.map((entry) => entry.value);
    const found = findShellIndex(values);
    if (!found)
        return undefined;
    const shell = values[found.index];
    for (let index = found.index + 1; index < values.length; index += 1) {
        const value = values[index];
        if (value === "--")
            continue;
        if (value === "-c" || value === "--command") {
            const script = entries[index + 1];
            if (script)
                return { shell, script, wrapper: found.wrapper };
            return undefined;
        }
        // bash -exc '...' and friends. Do not treat a bare -c as the script.
        if (/^-[^-]*c/.test(value)) {
            const script = entries[index + 1];
            if (script)
                return { shell, script, wrapper: found.wrapper };
            return undefined;
        }
        if (value.startsWith("-") && !value.startsWith("--"))
            continue;
    }
    return undefined;
}
function shellForEntries(entries) {
    if (entries.length === 0)
        return undefined;
    const values = entries.map((entry) => entry.value);
    const found = findShellIndex(values);
    return found ? { shell: values[found.index], wrapper: found.wrapper } : undefined;
}
/** Find command substitutions in a heredoc body without treating plain data lines as commands. */
function embeddedOnly(source, start, end) {
    const found = [];
    let position = start;
    while (position < end) {
        if (source[position] === "\\") {
            position += Math.min(2, end - position);
            continue;
        }
        if (source.startsWith("$(", position)) {
            if (source.startsWith("$((", position)) {
                const arithmeticEnd = consumeArithmeticExpansion(source, position, end);
                if (arithmeticEnd !== undefined) {
                    position = arithmeticEnd;
                    continue;
                }
            }
            const nested = consumeCommandSubstitution(source, position, end);
            if (nested) {
                found.push({ kind: "substitution", start: nested.innerStart, end: nested.innerEnd });
                position = nested.close + 1;
                continue;
            }
        }
        if (source[position] === "`") {
            const nested = consumeBacktick(source, position, end);
            if (nested) {
                found.push({ kind: "backtick", start: nested.innerStart, end: nested.innerEnd });
                position = nested.close + 1;
                continue;
            }
        }
        position += 1;
    }
    return found;
}
function commandSpan(tokens) {
    const first = tokens[0];
    const last = tokens[tokens.length - 1];
    return first && last ? { start: first.start, end: last.end } : undefined;
}
function parseScript(source, start, end, state, origin, wrapper, depth, sourceId) {
    if (depth > state.options.maxDepth || start > end) {
        state.warnings.push("nested shell depth exceeded");
        return;
    }
    const scan = scanShell(source, start, end);
    state.warnings.push(...scan.warnings);
    const segments = splitSegments(scan);
    for (const segment of segments) {
        const span = commandSpan(segment.tokens);
        if (!span)
            continue;
        const parsed = commandEntries(segment.tokens);
        if (parsed.command.length === 0)
            continue;
        const command = canonicalTokens(segment.tokens);
        const argv = parsed.command.map((entry) => entry.value);
        const executable = argv[0] ?? "";
        const mappedSpan = state.sourceSpans.get(sourceId);
        const key = `${sourceId}:${span.start}:${span.end}:${origin}:${wrapper ?? ""}`;
        if (!state.seen.has(key)) {
            state.seen.add(key);
            state.commands.push({
                command,
                executable,
                argv,
                start: mappedSpan?.start ?? span.start,
                end: mappedSpan?.end ?? span.end,
                origin,
                ...(wrapper ? { wrapper } : {}),
            });
        }
        // env/sudo can wrap an ordinary executable as well as a shell. Keep the
        // outer command for provenance, then expose the effective executable so a
        // guard never has to pattern-match through wrapper flags itself.
        const wrapped = findWrappedCommand(argv);
        if (wrapped && wrapped.index > 0) {
            const inner = parsed.command.slice(wrapped.index);
            const innerStart = inner[0]?.token.start ?? span.start;
            const innerArgv = inner.map((entry) => entry.value);
            const innerKey = `${sourceId}:${innerStart}:${span.end}:wrapper:${wrapped.wrapper}`;
            if (!state.seen.has(innerKey) && innerArgv.length > 0) {
                state.seen.add(innerKey);
                state.commands.push({
                    command: inner.map((entry) => shellQuote(entry.value)).join(" "),
                    executable: innerArgv[0] ?? "",
                    argv: innerArgv,
                    start: mappedSpan?.start ?? innerStart,
                    end: mappedSpan?.end ?? span.end,
                    origin: "wrapper",
                    wrapper: wrapped.wrapper,
                });
            }
        }
        // `$()` and backticks inside any word execute nested shell code. Parsing
        // their ranges is safe because quoted/data words remain one outer argv.
        for (const token of segment.tokens) {
            for (const embedded of token.embedded ?? []) {
                parseScript(source, embedded.start, embedded.end, state, embedded.kind, undefined, depth + 1, sourceId);
            }
        }
        const shellScript = findShellScriptArgument(parsed.command);
        if (shellScript && depth < state.options.maxDepth) {
            const nestedSource = shellScript.script.value;
            const nestedId = state.nextSourceId++;
            state.sourceSpans.set(nestedId, { start: shellScript.script.token.start, end: shellScript.script.token.end });
            parseScript(nestedSource, 0, nestedSource.length, state, "wrapper", shellScript.wrapper, depth + 1, nestedId);
        }
        const shellInfo = shellForEntries(parsed.command);
        if (shellInfo && depth < state.options.maxDepth) {
            for (const heredoc of segment.heredocs) {
                if (!heredoc.quoted) {
                    for (const embedded of embeddedOnly(source, heredoc.bodyStart, heredoc.bodyEnd)) {
                        parseScript(source, embedded.start, embedded.end, state, embedded.kind, undefined, depth + 1, sourceId);
                    }
                }
                parseScript(source, heredoc.bodyStart, heredoc.bodyEnd, state, "heredoc", shellInfo.wrapper, depth + 1, sourceId);
            }
        }
        else {
            // A heredoc fed to cat/python/etc. is data, not a shell script. Only
            // unquoted command substitutions in it are executable expansions.
            for (const heredoc of segment.heredocs) {
                if (heredoc.quoted)
                    continue;
                for (const embedded of embeddedOnly(source, heredoc.bodyStart, heredoc.bodyEnd)) {
                    parseScript(source, embedded.start, embedded.end, state, embedded.kind, undefined, depth + 1, sourceId);
                }
            }
        }
    }
}
/** Parse shell syntax and return commands at all execution levels. */
export function parseShell(source, options = {}) {
    const state = {
        commands: [],
        seen: new Set(),
        sourceSpans: new Map(),
        nextSourceId: 1,
        options: { maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH },
        warnings: [],
    };
    parseScript(source, 0, source.length, state, "top-level", undefined, 0, 0);
    state.commands.sort((left, right) => left.start - right.start || right.end - left.end || left.origin.localeCompare(right.origin));
    return { normalized: normalizeShellCommand(source), commands: state.commands, warnings: [...new Set(state.warnings)] };
}
/** Extract commands directly, convenient for guards that only need argv. */
export function extractShellCommands(source, options = {}) {
    return parseShell(source, options).commands;
}
/** Canonicalize shell words/operators without executing expansion or data. */
export function normalizeShellCommand(source) {
    return canonicalTokens(scanShell(source, 0, source.length).tokens);
}
