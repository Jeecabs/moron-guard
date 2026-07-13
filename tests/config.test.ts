import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadMoronConfig } from "../src/config.ts";

test("loads project config and environment overrides", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "moron-config-"));
  await writeFile(join(cwd, ".moron-guard.json"), JSON.stringify({
    enabled: false,
    categories: ["git", "filesystem"],
    allow: ["git status"],
    maxDepth: 12,
  }));

  const config = loadMoronConfig(cwd, { MORON_GUARD_CATEGORIES: "database", MORON_GUARD_ALLOW: "psql -c safe" } as NodeJS.ProcessEnv);
  assert.equal(config.enabled, undefined);
  assert.equal(config.path, join(cwd, ".moron-guard.json"));
  const trusted = loadMoronConfig(cwd, { MORON_GUARD_ALLOW_PROJECT_CONFIG: "1" } as NodeJS.ProcessEnv);
  assert.equal(trusted.enabled, false);
  assert.deepEqual(config.options.categories, ["database"]);
  assert.deepEqual(config.options.allow, ["psql -c safe"]);
  assert.equal(config.options.maxDepth, 12);
});

test("invalid explicit config is recoverable and bounded", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "moron-config-"));
  const config = loadMoronConfig(cwd, { MORON_GUARD_CONFIG: "missing.json", MORON_GUARD_MAX_DEPTH: "999" } as NodeJS.ProcessEnv);
  assert.equal(config.options.maxDepth, 8);
  assert.equal(config.warnings.length, 1);
});
