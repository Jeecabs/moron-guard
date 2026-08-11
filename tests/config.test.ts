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
  assert.equal(config.options.maxDepth, 8);
  assert.equal(trusted.options.maxDepth, 12);
  assert.deepEqual(trusted.options.categories, ["git", "filesystem"]);
  assert.deepEqual(trusted.options.allow, ["git status"]);
});

test("untrusted project config cannot weaken policy", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "moron-config-"));
  await writeFile(join(cwd, ".moron-guard.json"), JSON.stringify({
    enabled: false,
    mode: "audit",
    failClosed: false,
    userBash: false,
    categories: ["git"],
    allow: ["rm -rf /"],
    maxDepth: 1,
    maxCommandBytes: 1024 * 1024,
  }));

  const config = loadMoronConfig(cwd, {} as NodeJS.ProcessEnv);
  assert.equal(config.enabled, undefined);
  assert.equal(config.mode, "enforce");
  assert.equal(config.failClosed, true);
  assert.equal(config.userBash, true);
  assert.equal(config.options.categories, undefined);
  assert.equal(config.options.allow, undefined);
  assert.equal(config.options.maxDepth, 8);
  assert.equal(config.maxCommandBytes, 256 * 1024);
  assert.match(config.warnings.join("\n"), /enabled, mode, failClosed, userBash, categories, allow, maxDepth, maxCommandBytes/);

  const trusted = loadMoronConfig(cwd, { MORON_GUARD_ALLOW_PROJECT_CONFIG: "1" } as NodeJS.ProcessEnv);
  assert.equal(trusted.enabled, false);
  assert.equal(trusted.mode, "audit");
  assert.equal(trusted.failClosed, false);
  assert.equal(trusted.userBash, false);
  assert.deepEqual(trusted.options.categories, ["git"]);
  assert.deepEqual(trusted.options.allow, ["rm -rf /"]);
  assert.equal(trusted.options.maxDepth, 1);
  assert.equal(trusted.maxCommandBytes, 1024 * 1024);
});

test("benign project config does not weaken inherited global policy", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "moron-config-"));
  const agentDir = await mkdtemp(join(tmpdir(), "moron-agent-"));
  await writeFile(join(agentDir, "moron-guard.json"), JSON.stringify({ enabled: false, mode: "off", failClosed: false }));
  await writeFile(join(cwd, ".moron-guard.json"), JSON.stringify({ enabled: true }));

  const config = loadMoronConfig(cwd, { PI_AGENT_DIR: agentDir } as NodeJS.ProcessEnv);
  assert.equal(config.enabled, true);
  assert.equal(config.mode, "off");
  assert.equal(config.failClosed, false);
  assert.equal(config.warnings.length, 0);
});

test("invalid explicit config is recoverable and bounded", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "moron-config-"));
  const config = loadMoronConfig(cwd, { MORON_GUARD_CONFIG: "missing.json", MORON_GUARD_MAX_DEPTH: "999" } as NodeJS.ProcessEnv);
  assert.equal(config.options.maxDepth, 8);
  assert.equal(config.warnings.length, 1);
});
