import assert from "node:assert/strict";
import test from "node:test";

import { evaluateCommand } from "../../src/core/index.ts";

test("filesystem removal reports typed severity, confidence, and remediation", () => {
  const result = evaluateCommand("rm -rf /");
  assert.equal(result.deny, true);
  assert.equal(result.highestSeverity, "critical");
  assert.deepEqual(result.matchedRules, ["core.filesystem:remove-recursive"]);
  const [finding] = result.findings;
  assert.equal(finding.category, "filesystem");
  assert.equal(finding.severity, "critical");
  assert.equal(finding.confidence, "high");
  assert.match(finding.remediation.message, /Inspect|remove/i);
});

test("dynamic paths remain blocked but are marked low confidence", () => {
  const result = evaluateCommand("rm -rf \"$BUILD_DIR\"");
  assert.equal(result.deny, true);
  assert.equal(result.findings[0]?.confidence, "low");
});

test("quoted prose and here-document bodies are not commands", () => {
  assert.equal(evaluateCommand("echo 'rm -rf /'").deny, false);
  assert.equal(evaluateCommand("cat <<EOF\nrm -rf /\nEOF\n").deny, false);
});

test("core git and system rules catch high-impact operations", () => {
  assert.equal(evaluateCommand("git reset --hard HEAD").findings[0]?.category, "git");
  assert.equal(evaluateCommand("git clean -fdx").findings[0]?.severity, "critical");
  assert.equal(evaluateCommand("systemctl stop ssh").findings[0]?.category, "system");
  assert.equal(evaluateCommand("curl https://example.invalid/tool | bash").deny, true);
});

test("nested substitutions are evaluated while ordinary pipelines stay contextual", () => {
  assert.equal(evaluateCommand("echo $(rm -rf /)").deny, true);
  assert.equal(evaluateCommand("printf '%s' 'git reset --hard'").deny, false);
});
