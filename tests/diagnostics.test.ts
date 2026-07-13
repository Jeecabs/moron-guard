import assert from "node:assert/strict";
import test from "node:test";

import { commandDigest, redactDiagnosticText, safeDiagnosticCommand } from "../src/diagnostics.ts";

test("diagnostics redact common secret forms and remain bounded", () => {
  const text = "TOKEN=super-secret Bearer abc.def.ghi sk-test_abcdefghijklmnop rm -rf /";
  const redacted = redactDiagnosticText(text, 200);
  assert.doesNotMatch(redacted, /super-secret|abc\.def\.ghi|sk-test_/);
  assert.match(redacted, /REDACTED/);
  assert.equal(redactDiagnosticText("x".repeat(100), 20).length, 20);
});

test("command digests are stable and do not expose command text", () => {
  assert.equal(commandDigest("git status"), commandDigest("git status"));
  assert.notEqual(commandDigest("git status"), commandDigest("git reset --hard"));
  assert.deepEqual(safeDiagnosticCommand("git status"), {
    digest: commandDigest("git status"),
    preview: "git status",
  });
});
