import assert from "node:assert/strict";
import test from "node:test";

import {
  extractShellCommands,
  normalizeShellCommand,
  parseShell,
} from "../src/shell-parser.ts";

const executables = (source: string) => extractShellCommands(source).map((command) => command.executable);

 test("normalizes continuations and ignores comments outside words", () => {
  assert.equal(normalizeShellCommand("rm \\\n -rf / # rm -rf /"), "rm -rf /");
  assert.deepEqual(executables("echo foo#bar # rm -rf /"), ["echo"]);
});

test("quotes keep separators and dangerous-looking data inside one argv", () => {
  const commands = extractShellCommands("echo 'rm -rf /; reboot' && printf '%s' \"# rm\"");
  assert.deepEqual(commands.map((command) => command.executable), ["echo", "printf"]);
  assert.deepEqual(commands[0]?.argv, ["echo", "rm -rf /; reboot"]);
});

test("separators expose each command without splitting quoted separators", () => {
  assert.deepEqual(executables("true; rm -rf / || echo 'rm; rm'"), ["true", "rm", "echo"]);
});

test("command substitutions and backticks are recursively extracted", () => {
  const commands = extractShellCommands("echo \$(rm -rf /) && echo `chmod 777 /tmp/x`");
  assert.deepEqual(commands.map((command) => command.executable), ["echo", "rm", "echo", "chmod"]);
  assert.equal(commands[1]?.origin, "substitution");
  assert.equal(commands[3]?.origin, "backtick");
});

test("parameter expansion keeps braces together and arithmetic is data", () => {
  assert.deepEqual(executables("echo ${fallback:-$(rm -rf /)}; echo $((rm))"), ["echo", "rm", "echo"]);
});

test("env and sudo wrappers cannot hide sh -c scripts", () => {
  const commands = extractShellCommands("env FOO=bar sudo -n sh -c 'rm -rf /; echo done'");
  assert.deepEqual(commands.map((command) => command.executable), ["env", "sh", "rm", "echo"]);
  assert.equal(commands[2]?.wrapper, "env sudo sh");
  assert.equal(commands[2]?.start, 26);
});

test("env and sudo expose the effective non-shell command", () => {
  const commands = extractShellCommands("sudo -- env -i rm -rf /tmp/x");
  assert.deepEqual(commands.map((command) => command.executable), ["sudo", "rm"]);
  assert.equal(commands[1]?.wrapper, "sudo env");
});

test("shell -c options with bundled flags are extracted", () => {
  const commands = extractShellCommands("bash -euc 'echo ok; rm -f x'");
  assert.deepEqual(commands.map((command) => command.executable), ["bash", "echo", "rm"]);
  assert.equal(commands[1]?.origin, "wrapper");
});

test("heredoc data is not mistaken for a command", () => {
  const commands = extractShellCommands("cat <<'DATA'\nrm -rf /\nDATA\necho ok");
  assert.deepEqual(commands.map((command) => command.executable), ["cat", "echo"]);
});

test("shell heredocs are parsed as inline scripts", () => {
  const commands = extractShellCommands("sudo sh <<-EOF\n\trm -rf /\n\techo done\nEOF");
  assert.deepEqual(commands.map((command) => command.executable), ["sudo", "sh", "rm", "echo"]);
  assert.equal(commands[2]?.origin, "heredoc");
  assert.equal(commands[2]?.wrapper, "sudo sh");
});

test("unquoted heredoc substitutions execute, quoted heredoc substitutions do not", () => {
  assert.deepEqual(executables("cat <<EOF\n$(rm -rf /)\nEOF"), ["cat", "rm"]);
  assert.deepEqual(executables("cat <<'EOF'\n$(rm -rf /)\nEOF"), ["cat"]);
});

test("redirections do not become argv", () => {
  const command = extractShellCommands("echo hi 2>/tmp/out")[0];
  assert.deepEqual(command?.argv, ["echo", "hi"]);
});

test("parse result includes canonical top-level normalization", () => {
  const result = parseShell("echo 'hello world' && true");
  assert.equal(result.normalized, "echo 'hello world' && true");
  assert.equal(result.commands.length, 2);
});
