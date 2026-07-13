import assert from "node:assert/strict";
import test from "node:test";

import { evaluateCommand } from "../src/core/evaluate.ts";

test("blocks destructive git and filesystem commands", () => {
  for (const command of [
    "git reset --hard HEAD",
    "git clean -fdx",
    "rm -rf ./src",
    "rm -r ..",
    "dd if=/dev/zero of=/dev/disk9",
  ]) {
    const result = evaluateCommand(command, { context: { cwd: "/repo" } });
    assert.equal(result.deny, true, command);
    assert.ok(result.findings.length > 0, command);
  }
});

test("does not flag dangerous-looking text or safe temp cleanup", () => {
  for (const command of [
    "echo 'rm -rf /'",
    "grep -R 'git reset --hard' .",
    "rm -rf /tmp/moron-build",
    "cat <<'EOF'\nrm -rf /\nEOF",
  ]) {
    assert.equal(evaluateCommand(command).deny, false, command);
  }
});

test("unwraps shell wrappers and command substitutions", () => {
  for (const command of [
    "env FOO=bar sudo sh -c 'git reset --hard'",
    "echo $(rm -rf ./src)",
    "bash -c 'docker compose down -v'",
  ]) {
    const result = evaluateCommand(command, { context: { cwd: "/repo" } });
    assert.equal(result.deny, true, command);
  }
});

test("covers database, container, remote, and permission packs", () => {
  const cases: Array<[string, string]> = [
    ["psql -c 'DROP TABLE users'", "database.sql-drop"],
    ["psql -c 'DELETE FROM users'", "database.sql-unbounded-mutation"],
    ["docker system prune --force", "containers.docker-system-prune"],
    ["rsync --delete ./dist host:/srv/app", "remote.rsync-delete"],
    ["chmod -R 777 .", "core.permissions:chmod-broad"],
    ["pnpm store prune", "package-manager.pnpm-store-prune"],
    ["aws ec2 terminate-instances --instance-ids i-123", "cloud.aws-resource-delete"],
    ["psql -f ./hidden.sql", "database.opaque-script-file"],
  ];
  for (const [command, ruleId] of cases) {
    const result = evaluateCommand(command, { context: { cwd: "/repo" } });
    assert.ok(result.matchedRules.includes(ruleId), `${command}: ${result.matchedRules.join(", ")}`);
  }
});

test("allowlist applies exact normalized command only", () => {
  assert.equal(evaluateCommand("rm -rf /tmp/build", { allow: ["rm -rf /tmp/build"] }).deny, false);
  assert.equal(evaluateCommand("rm -rf /", { allow: ["rm -rf /tmp/build"] }).deny, true);
  assert.equal(evaluateCommand("rm -rf /", { allow: ["re:.*"] }).deny, true);
});
