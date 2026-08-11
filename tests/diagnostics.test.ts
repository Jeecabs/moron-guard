import assert from "node:assert/strict";
import test from "node:test";

import { createGuard } from "../src/api.ts";
import { commandDigest, redactDiagnosticText, safeDiagnosticCommand } from "../src/diagnostics.ts";
import { formatBlock } from "../src/index.ts";

test("diagnostics redact common secret forms and remain bounded", () => {
  const text = "TOKEN=super-secret Bearer abc.def.ghi sk-test_abcdefghijklmnop rm -rf /";
  const redacted = redactDiagnosticText(text, 200);
  assert.doesNotMatch(redacted, /super-secret|abc\.def\.ghi|sk-test_/);
  assert.match(redacted, /REDACTED/);
  assert.equal(redactDiagnosticText("x".repeat(100), 20).length, 20);
  assert.equal(redactDiagnosticText("cat /Users/lachlan/private.txt /home/alice/key C:\\Users\\Bob\\token"), "cat ~/private.txt ~/key ~\\token");
});

test("blocked command output does not repeat secrets or home directories", () => {
  const command = "TOKEN=super-secret rm -rf /Users/lachlan/private";
  const output = formatBlock(command, createGuard().decide(command));
  assert.doesNotMatch(output, /super-secret|\/Users\/lachlan/);
  assert.match(output, /TOKEN=\[REDACTED\]/);
  assert.match(output, /command id: sha256:[a-f0-9]{16}/);
});

test("command digests are stable and do not expose command text", () => {
  assert.equal(commandDigest("git status"), commandDigest("git status"));
  assert.notEqual(commandDigest("git status"), commandDigest("git reset --hard"));
  assert.deepEqual(safeDiagnosticCommand("git status"), {
    digest: commandDigest("git status"),
    preview: "git status",
  });
});
