import assert from "node:assert/strict";
import test from "node:test";

import { createGuard } from "../src/api.ts";

test("native Guard API returns structured deny decision without Pi types", () => {
  const guard = createGuard({ context: { cwd: "/repo" } });
  const decision = guard.evaluate({ command: "git reset --hard HEAD" });
  assert.equal(decision.action, "deny");
  assert.equal(decision.enforce, true);
  assert.equal(decision.source, "native");
  assert.equal(decision.diagnostics[0]?.code, "core.git:reset-hard");
  assert.equal(decision.diagnostics[0]?.kind, "finding");
  assert.equal(decision.diagnostics[0]?.category, "git");
});

test("Guard status and explain are deterministic", () => {
  const guard = createGuard({ maxDepth: 4 });
  const status = guard.status();
  assert.equal(status.ready, true);
  assert.equal(status.engine, "native");
  assert.equal(status.maxDepth, 4);
  const explanation = guard.explain("git status");
  assert.equal(explanation.action, "allow");
  assert.equal(explanation.normalized, "git status");
});

test("cache keys include cwd and expose bounded metrics", () => {
  const guard = createGuard({ cacheMax: 2, cacheTtlMs: 1000 });
  guard.decide({ command: "git status", options: { context: { cwd: "/one" } } });
  guard.decide({ command: "git status", options: { context: { cwd: "/one" } } });
  guard.decide({ command: "git status", options: { context: { cwd: "/two" } } });
  const cache = guard.status().cache;
  assert.equal(cache?.hits, 1);
  assert.equal(cache?.misses, 2);
  assert.equal(cache?.entries, 2);
  guard.clearCache();
  assert.equal(guard.status().cache?.entries, 0);
});

test("malformed shell syntax fails closed as unknown", () => {
  const decision = createGuard().decide("echo 'unterminated");
  assert.equal(decision.action, "error");
  assert.equal(decision.enforce, true);
  assert.equal(decision.diagnostics.at(-1)?.code, "guard.unknown-syntax");
});

test("opaque dynamic shell scripts fail closed", () => {
  const decision = createGuard().decide("bash -c \"$SCRIPT\"");
  assert.equal(decision.action, "error");
  assert.equal(decision.enforce, true);
});

test("invalid command produces host-neutral error", () => {
  const decision = createGuard().decide({ command: 42 as unknown as string });
  assert.equal(decision.action, "error");
  assert.equal(decision.diagnostics[0]?.code, "guard.invalid-command");
});
