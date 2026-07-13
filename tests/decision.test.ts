import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { dcgDecision, parseDcgDecision } from "../src/decision.ts";

test("denied robot result preserves dcg metadata", () => {
  const decision = parseDcgDecision(1, JSON.stringify({
    decision: "deny",
    reason: "git reset --hard destroys uncommitted changes",
    rule_id: "core.git:reset-hard",
    pack_id: "core.git",
    remediation: "stash changes first",
  }));

  assert.equal(decision.status, "denied");
  assert.equal(decision.deny, true);
  assert.equal(decision.reason, "git reset --hard destroys uncommitted changes");
  assert.equal(decision.ruleId, "core.git:reset-hard");
  assert.equal(decision.packId, "core.git");
  assert.equal(decision.remediation, "stash changes first");
});

test("exit code one denies even when dcg output is malformed", () => {
  assert.equal(parseDcgDecision(1, "not-json").deny, true);
});

test("successful and unavailable results are distinct", () => {
  assert.deepEqual(parseDcgDecision(0, JSON.stringify({ decision: "allow" })), {
    status: "allowed",
    deny: false,
  });
  assert.equal(parseDcgDecision(3, "{}").status, "unavailable");
});

test("nested robot payloads are supported", () => {
  const decision = parseDcgDecision(0, JSON.stringify({
    success: false,
    data: { decision: "deny", reason: "danger" },
  }));
  assert.equal(decision.deny, true);
  assert.equal(decision.reason, "danger");
});

test("dcgDecision invokes configured binary without a shell", async () => {
  const dir = await mkdtemp(join(tmpdir(), "moron-guard-"));
  const fakeDcg = join(dir, "dcg");
  await writeFile(fakeDcg, "#!/bin/sh\nprintf '{\\\"decision\\\":\\\"deny\\\",\\\"reason\\\":\\\"test block\\\"}'\nexit 1\n");
  await chmod(fakeDcg, 0o755);

  const decision = await dcgDecision("rm -rf /", { bin: fakeDcg, timeoutMs: 1000 });
  assert.equal(decision.status, "denied");
  assert.equal(decision.reason, "test block");
});

test("missing dcg fails open by default and can fail closed", async () => {
  const open = await dcgDecision("danger", { bin: "/definitely/missing/dcg", timeoutMs: 1000 });
  assert.equal(open.status, "unavailable");
  assert.equal(open.deny, false);

  const closed = await dcgDecision("danger", { bin: "/definitely/missing/dcg", failClosed: true, timeoutMs: 1000 });
  assert.equal(closed.status, "unavailable");
  assert.equal(closed.deny, true);
});
