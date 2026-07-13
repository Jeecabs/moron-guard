import assert from "node:assert/strict";
import test from "node:test";

import { extractShellCommands } from "../src/shell-parser.ts";
import { evaluateCommand } from "../src/core/index.ts";

/**
 * Security corpus ported from destructive_command_guard's tests/corpus:
 * bypass_attempts/{obfuscation,wrappers,heredoc_inline}.toml,
 * canonical.toml, and false_positives/*.toml.
 *
 * These tests never execute a command. Parser assertions inspect extracted
 * argv/origins; evaluator assertions inspect the public deny/allow result for
 * shell text that would be passed to bash. A deny case means at least one
 * finding must be returned; an allow case is intentionally a command/data
 * example that must not be mistaken for execution.
 */
interface SecurityCase {
  name: string;
  command: string;
  expected: "deny" | "allow";
}

function assertCorpus(corpusName: string, cases: readonly SecurityCase[]): void {
  for (const fixture of cases) {
    const result = evaluateCommand(fixture.command);
    assert.equal(
      result.deny,
      fixture.expected === "deny",
      `${corpusName}/${fixture.name}: expected ${fixture.expected}, got ${result.deny ? "deny" : "allow"}\n` +
        `command: ${JSON.stringify(fixture.command)}\n` +
        `rules: ${result.matchedRules.join(", ") || "none"}`,
    );
  }
}

/** Keep upstream-derived cases visible as hard Moron Guard contracts. */
function securityCorpus(corpusName: string, cases: readonly SecurityCase[], rationale: string): void {
  test(`security corpus: ${corpusName} — ${rationale}`, () => {
    assertCorpus(corpusName, cases);
  });
}

const deny = (name: string, command: string): SecurityCase => ({ name, command, expected: "deny" });
const allow = (name: string, command: string): SecurityCase => ({ name, command, expected: "allow" });

const shellObfuscation: SecurityCase[] = [
  deny("absolute git path", "/usr/bin/git reset --hard"),
  deny("env git", "env git reset --hard"),
  deny("leading whitespace", "  git reset --hard"),
  deny("trailing whitespace", "git reset --hard  "),
  deny("extra rm whitespace", "rm   -rf   /"),
  deny("rm flags separate", "rm -f -r /"),
  deny("rm flags reversed", "rm -fr /"),
  deny("escaped command word", String.raw`\git reset --hard`),
  deny("escaped letters", String.raw`g\it reset --hard`),
  deny("split quoted letters", "g'i't reset --hard"),
  deny("quoted command word", '"git" reset --hard'),
  deny("quoted subcommand", 'git "reset" --hard'),
  deny("line continuation", "git reset \\\n--hard"),
  deny("newline separator", "git\nreset --hard"),
  deny("command substitution", "echo $(git reset --hard)"),
  deny("backtick substitution", "echo `git reset --hard`"),
  deny("shell -c", "bash -c 'git reset --hard'"),
  deny("nested shell rm", "sh -c 'rm -rf /'"),
];

test("security corpus: shell obfuscation", () => {
  assertCorpus("shell-obfuscation", shellObfuscation);
});

test("parser/evaluator contract: spaced git clean flags are argv, not prose", () => {
  const [parsed] = extractShellCommands("git clean -d -f");
  assert.deepEqual(parsed?.argv, ["git", "clean", "-d", "-f"]);
  assert.equal(evaluateCommand("git clean -d -f").deny, true);
});

test("parser contract: wrappers and nested substitutions remain executable commands", () => {
  const commands = extractShellCommands("sudo env git reset --hard && echo $(rm -rf /) && echo `git clean -fd`");
  assert.ok(commands.some((command) => command.executable === "git" && command.origin === "wrapper"));
  assert.ok(commands.some((command) => command.executable === "rm" && command.origin === "substitution"));
  assert.ok(commands.some((command) => command.executable === "git" && command.origin === "backtick"));
});

test("parser contract: executable heredocs are scanned, cat heredocs remain data", () => {
  const executable = extractShellCommands(String.raw`bash <<\EOF
rm -rf /
EOF`);
  assert.ok(executable.some((command) => command.executable === "rm" && command.origin === "heredoc"));

  const data = extractShellCommands(String.raw`cat <<\EOF
rm -rf /
EOF`);
  assert.deepEqual(data.map((command) => command.executable), ["cat"]);
});

const wrappers: SecurityCase[] = [
  deny("sudo git reset", "sudo git reset --hard"),
  deny("sudo rm", "sudo rm -rf /home/user"),
  deny("sudo clean", "sudo git clean -fd"),
  deny("sudo force push", "sudo git push --force origin main"),
  deny("env assignment", "env GIT_AUTHOR_NAME=test git reset --hard"),
  deny("env -i", "env -i git reset --hard"),
  deny("command wrapper", "command git reset --hard"),
  deny("doas wrapper", "doas git reset --hard"),
  deny("exec wrapper", "exec git reset --hard"),
  deny("time wrapper", "time git reset --hard"),
  deny("time rm", "time rm -rf /home/user"),
  deny("nohup wrapper", "nohup git reset --hard"),
  deny("nice wrapper", "nice -n 19 rm -rf /home/user"),
  deny("multiple wrappers", "sudo env git reset --hard"),
  deny("reverse multiple wrappers", "env sudo git reset --hard"),
  deny("env option command substitution", "env -C /tmp/$(rm -rf /home/user) git status"),
  deny("env attached option substitution", "env --chdir=$(rm -rf /home/user) git status"),
  deny("env backtick option substitution", "env -C `rm -rf /home/user` git status"),
  deny("sudo option substitution", "sudo -u $(rm -rf /home/user) git status"),
  deny("sudo attached option substitution", "sudo -D/tmp/$(rm -rf /home/user) git status"),
  deny("xargs shell", "xargs sh -c 'rm -rf /'"),
  deny("find exec removal", "find . -exec rm -rf / {} +"),
];

test("security corpus: wrappers cannot hide a destructive command", () => {
  assertCorpus("wrappers", wrappers);
});

const gitDestructive: SecurityCase[] = [
  deny("reset hard", "git reset --hard"),
  deny("reset hard ref", "git reset --hard HEAD~5"),
  deny("global option reset", "git -C /tmp reset --hard"),
  deny("work-tree clean", "git --work-tree=/tmp clean -fd"),
  deny("clean force", "git clean -fd"),
  deny("clean ignored files", "git clean -fdx"),
  deny("checkout tracked files", "git checkout -- file.txt"),
  deny("restore worktree", "git restore file.txt"),
  deny("stash drop", "git stash drop"),
  deny("stash clear", "git stash clear"),
  deny("force branch delete", "git branch -D feature-branch"),
  deny("force push short", "git push -f origin main"),
  deny("force push long", "git push --force origin main"),
  deny("force push with lease", "git push --force-with-lease origin main"),
  deny("history filter", "git filter-branch --force -- --all"),
  deny("gc prune now", "git gc --prune=now"),
  deny("reflog expire", "git reflog expire --expire=now --all"),
];

test("security corpus: destructive git operations", () => {
  assertCorpus("git", gitDestructive);
});

const rmDestructive: SecurityCase[] = [
  deny("root", "rm -rf /"),
  deny("home", "rm -rf ~"),
  deny("home variable", "rm -rf $HOME"),
  deny("glob", "rm -rf *"),
  deny("hidden glob", "rm -rf .*"),
  deny("relative tree", "rm -rf ./build"),
  deny("long flags", "rm --recursive --force /etc"),
  deny("separate flags", "rm -r -f ./build"),
  deny("uppercase recursive", "rm -R -f /home/user"),
  deny("find delete root", "find / -delete"),
  deny("shred sensitive file", "shred -uvz /etc/passwd"),
  deny("unlink sensitive file", "unlink /etc/passwd"),
  deny("raw disk write", "dd if=image of=/dev/sda"),
  deny("filesystem format", "mkfs.ext4 /dev/sda"),
  deny("overwrite device", "echo data > /dev/sda"),
];

test("security corpus: destructive rm and filesystem operations", () => {
  assertCorpus("rm", rmDestructive);
});

const postgresDestructive: SecurityCase[] = [
  // database.postgresql is an upstream optional pack. These cases are kept in
  // this corpus even though the built-in core evaluator currently has no SQL
  // rule family; failures are an explicit coverage gap, not safe behavior.
  deny("truncate", 'psql -c "TRUNCATE TABLE sessions;"'),
  deny("delete without where", 'psql -c "DELETE FROM audit_log;"'),
  deny("drop database", 'psql -c "DROP DATABASE production;"'),
  deny("drop database cli", "dropdb production"),
  deny("drop table", 'psql -c "DROP TABLE users;"'),
  deny("drop schema cascade", 'psql -c "DROP SCHEMA public CASCADE;"'),
  deny("wrapped drop database", "sudo psql -c 'DROP DATABASE production;'"),
  deny("sql heredoc", String.raw`psql <<'SQL'
DROP DATABASE production;
SQL`),
  deny("sql comment separator", 'psql -c "TRUNCATE/**/TABLE sessions;"'),
];

securityCorpus(
  "postgres",
  postgresDestructive,
  "SQL payload rules are evaluated from command arguments and heredocs",
);

const heredocExecution: SecurityCase[] = [
  deny("bash heredoc", String.raw`bash <<EOF
git reset --hard
EOF`),
  deny("sh heredoc", String.raw`sh <<EOF
rm -rf /home/user
EOF`),
  deny("tab-stripped heredoc", `bash <<-EOF
\trm -rf /
EOF`),
  deny("python heredoc", String.raw`python - <<EOF
import shutil
shutil.rmtree('/tmp/demo')
EOF`),
  deny("quoted delimiter heredoc", String.raw`python3 << "EOF SPACE"
import shutil
shutil.rmtree('/tmp/demo')
EOF SPACE`),
  deny("bash here-string", "bash <<<'rm -rf /home/user'"),
  deny("sh here-string", "sh <<<'git reset --hard'"),
  deny("bash inline script", "bash -c 'rm -rf /etc/demo'"),
  deny("python inline script", 'python -c "import shutil; shutil.rmtree(\'/tmp/demo\')"'),
  deny("node inline child process", 'node -e "require(\'child_process\').execSync(\'rm -rf /\')"'),
  deny("perl inline system", 'perl -e "system(\'rm -rf /\')"'),
];

securityCorpus(
  "heredoc-evaluator",
  heredocExecution,
  "inline shell/interpreter payloads are evaluated before execution",
);

const safeExamples: SecurityCase[] = [
  allow("git status", "git status"),
  allow("git status flags", "git status --short --branch"),
  allow("git diff", "git diff HEAD~1"),
  allow("git checkout branch", "git checkout -b feature/one"),
  allow("git reset soft", "git reset --soft HEAD~1"),
  allow("git reset mixed", "git reset HEAD~1"),
  allow("git push without force", "git push origin main"),
  allow("git commit message", 'git commit -m "fix rm -rf detection"'),
  allow("command query", "command -v git"),
  allow("sudo status", "sudo git status"),
  allow("env status", "env FOO=1 git status"),
  allow("command status", "command git status"),
  allow("echo dangerous-looking text", 'echo "git reset --hard"'),
  allow("search dangerous-looking text", 'rg -n "rm -rf" README.md'),
  allow("shell comment", "# git reset --hard"),
  allow("trailing shell comment", "echo ok # rm -rf /"),
  allow("comment after separator", "echo ok; # git reset --hard"),
  allow("cat heredoc data", String.raw`cat <<EOF
rm -rf /
git reset --hard
EOF`),
  allow("tee heredoc data", String.raw`tee /tmp/example <<EOF
rm -rf /
EOF`),
  allow("grep heredoc data", String.raw`grep -F "rm -rf /" <<EOF
rm -rf /
EOF`),
];

test("security corpus: safe commands and non-executing data", () => {
  assertCorpus("safe", safeExamples);
});

securityCorpus(
  "safe-rm-policy",
  [
    allow("temp cleanup", "rm -rf /tmp/build"),
    allow("var temp cleanup", "rm -rf /var/tmp/build"),
    allow("temp variable cleanup", "rm -rf ${TMPDIR}/build"),
    allow("single-file remove", "rm file.txt"),
    allow("interactive remove", "rm -i file.txt"),
  ],
  "upstream safe-path policy is evaluator-specific; core currently treats rm conservatively",
);

/**
 * Adversarial probes copied from upstream's documented bypass corpus. These
 * stay hard assertions: a new rule or parser change must not make them pass.
 */
const knownBypasses: SecurityCase[] = [
  deny("force push equals", "git push --force=true origin main"),
  deny("eval rm", "eval 'rm -rf /'"),
  deny("eval git", "eval 'git reset --hard'"),
  deny("printf piped to sh", "printf 'rm -rf /\\n' | sh"),
  deny("variable command", "cmd='git reset --hard'; eval \"$cmd\""),
  deny("git checkout force", "git checkout -f main"),
  deny("builtin command wrapper", "builtin command git reset --hard"),
  deny("timeout wrapper", "timeout 10s rm -rf /"),
  deny("watch wrapper", "watch git reset --hard"),
  deny("strace wrapper", "strace git reset --hard"),
  deny("backslash heredoc delimiter", String.raw`python3 <<\EOF
import shutil
shutil.rmtree('/tmp/demo')
EOF`),
  deny("ruby inline removal", 'ruby -e "require \'fileutils\'; FileUtils.rm_rf(\'/tmp/demo\')"'),
  deny("quoted Windows git path", String.raw`"C:/Program Files/Git/bin/git.exe" reset --hard`),
  deny("branch delete long flags", "git branch --delete --force feature"),
];

securityCorpus(
  "known-bypass",
  knownBypasses,
  "adversarial wrapper and obfuscation contract",
);
