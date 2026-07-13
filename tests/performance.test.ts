import assert from "node:assert/strict";
import test from "node:test";

import { evaluateCommand } from "../src/core/index.ts";

test("oversize UTF-8 input fails closed before parsing", () => {
  const result = evaluateCommand("é".repeat(70_000));
  assert.equal(result.deny, true);
  assert.deepEqual(result.matchedRules, ["core.input:oversize"]);
  assert.match(result.warnings[0] ?? "", /UTF-8 bytes/);
});

test("bounded parser handles hostile nesting and large input", () => {
  const nested = "echo $(".repeat(6) + "rm -rf /" + ")".repeat(6);
  const large = `${"echo safe; ".repeat(2000)}${nested}`;
  const started = performance.now();
  const result = evaluateCommand(large, { maxDepth: 8 });
  const elapsed = performance.now() - started;

  assert.equal(result.deny, true);
  assert.ok(elapsed < 1000, `scanner took ${elapsed.toFixed(1)}ms`);
});
