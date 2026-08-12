import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = mkdtempSync(join(tmpdir(), "moron-guard-package-"));
const manifest = JSON.parse(readFileSync(join(projectRoot, "package.json"), "utf8"));
assert.equal(manifest.scripts.prepare, undefined, "Git installs must not build with omitted dev dependencies");
assert.equal(manifest.scripts.prepack, undefined, "Git installs must not run publish builds");
assert.equal(manifest.scripts.prepublish, undefined, "Git installs must not run publish checks");
const readme = readFileSync(join(projectRoot, "README.md"), "utf8");
const versionPattern = "(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)";
const npmVersions = [...readme.matchAll(new RegExp(`npm:moron-guard@${versionPattern}`, "g"))].map((match) => match[1]);
const gitVersions = [...readme.matchAll(new RegExp(`github\\.com/Jeecabs/moron-guard@v${versionPattern}`, "g"))].map((match) => match[1]);
assert(npmVersions.length >= 2, "README must show pinned npm install and trial versions");
assert(gitVersions.length >= 1, "README must show a pinned Git install version");
assert([...npmVersions, ...gitVersions].every((version) => version === manifest.version), "README install examples must match package.json version");

const WINDOWS = process.platform === "win32";
const NPM_EXECUTABLE = WINDOWS ? "npm.cmd" : "npm";
const PATH_SEPARATOR = WINDOWS ? ";" : ":";

function findConfiguredNpmCli() {
  const candidate = process.env.npm_execpath;
  const npmCliPattern = /(?:^|[/\\])npm(?:-cli)?\.(?:c?js)$/i;
  return candidate && npmCliPattern.test(candidate) && existsSync(candidate) ? candidate : undefined;
}

function findBundledNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    resolve(nodeDir, "../lib/node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDir, "node_modules/npm/bin/npm-cli.js"),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

function findNpmOnPath() {
  return (process.env.PATH ?? "")
    .split(PATH_SEPARATOR)
    .filter(Boolean)
    .map((directory) => join(directory, NPM_EXECUTABLE))
    .find((candidate) => existsSync(candidate));
}

function windowsNpmCommand(executable) {
  return { command: executable ?? "npm.cmd", prefix: [], shell: true };
}

function findNpmCommand() {
  const npmCli = [findConfiguredNpmCli(), findBundledNpmCli()].find(Boolean);
  if (npmCli) return { command: process.execPath, prefix: [npmCli], shell: false };

  const executable = findNpmOnPath();
  if (WINDOWS) return windowsNpmCommand(executable);
  if (executable) return { command: process.execPath, prefix: [realpathSync(executable)], shell: false };
  throw new Error("Unable to locate npm CLI");
}

const npmCommand = findNpmCommand();
const runNpm = (args, options = {}) => execFileSync(npmCommand.command, [...npmCommand.prefix, ...args], {
  cwd: options.cwd ?? projectRoot,
  encoding: options.encoding,
  shell: npmCommand.shell,
  stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
});

let tarballPath;
try {
  const packed = JSON.parse(runNpm(["pack", "--json", "--ignore-scripts"], { capture: true, encoding: "utf8" }));
  assert.equal(packed.length, 1, "npm pack must produce exactly one tarball");
  tarballPath = resolve(projectRoot, packed[0].filename);

  const packedPaths = new Set(packed[0].files.map(({ path }) => path));
  for (const expected of [
    "dist/api.js",
    "dist/api.d.ts",
    "dist/core/index.js",
    "dist/core/index.d.ts",
    "dist/diagnostics.js",
    "dist/diagnostics.d.ts",
    "dist/index.js",
    "dist/index.d.ts",
    "assets/moron-guard.png",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "RELEASING.md",
    "SECURITY.md",
    "SUPPORT.md",
  ]) {
    assert(packedPaths.has(expected), `packed artifact is missing ${expected}`);
  }
  assert(![...packedPaths].some((path) => path.startsWith("src/")), "packed artifact must not expose TypeScript source entrypoints");

  writeFileSync(join(tempRoot, "package.json"), JSON.stringify({ private: true, type: "module" }));
  runNpm([
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--no-package-lock",
    "--legacy-peer-deps",
    tarballPath,
  ], { cwd: tempRoot });

  writeFileSync(join(tempRoot, "runtime-smoke.mjs"), `
    import assert from "node:assert/strict";
    import { createGuard } from "moron-guard";
    import { evaluateCommand } from "moron-guard/core";
    import { safeDiagnosticCommand } from "moron-guard/diagnostics";
    import schema from "moron-guard/schema" with { type: "json" };
    import extension from "./node_modules/moron-guard/dist/index.js";

    assert.equal(createGuard().decide("rm -rf /").action, "deny");
    assert.equal(evaluateCommand("git status").allowed, true);
    assert.equal(safeDiagnosticCommand("echo ok").digest.length, 16);
    assert.equal(typeof schema.title, "string");
    assert.equal(typeof extension, "function");
  `);
  execFileSync(process.execPath, [join(tempRoot, "runtime-smoke.mjs")], { cwd: tempRoot, stdio: "inherit" });

  writeFileSync(join(tempRoot, "types-smoke.mts"), `
    import { createGuard, type Decision } from "moron-guard";
    import { evaluateCommand, type EvaluationResult } from "moron-guard/core";
    import { safeDiagnosticCommand } from "moron-guard/diagnostics";

    const decision: Decision = createGuard().decide("git status");
    const result: EvaluationResult = evaluateCommand("git status");
    const digest: string = safeDiagnosticCommand("echo ok").digest;
    void [decision, result, digest];
  `);
  writeFileSync(join(tempRoot, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      module: "NodeNext",
      moduleResolution: "NodeNext",
      noEmit: true,
      skipLibCheck: false,
      strict: true,
      target: "ES2022",
    },
    files: ["types-smoke.mts"],
  }));
  execFileSync(process.execPath, [join(projectRoot, "node_modules/typescript/bin/tsc"), "-p", join(tempRoot, "tsconfig.json")], {
    cwd: tempRoot,
    stdio: "inherit",
  });

  const installedManifest = JSON.parse(readFileSync(join(tempRoot, "node_modules/moron-guard/package.json"), "utf8"));
  assert.equal(installedManifest.pi.extensions[0], "./dist/index.js");
  console.log("Packed artifact runtime and TypeScript smoke tests passed.");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
  if (tarballPath) rmSync(tarballPath, { force: true });
}
