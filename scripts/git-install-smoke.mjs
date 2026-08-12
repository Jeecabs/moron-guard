import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = mkdtempSync(join(tmpdir(), "moron-guard-git-install-"));
const candidatePath = join(tempRoot, "candidate");
const consumerPath = join(tempRoot, "consumer");

const run = (command, args, options = {}) => execFileSync(command, args, {
  cwd: options.cwd ?? projectRoot,
  encoding: options.encoding,
  shell: options.shell ?? false,
  stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
});

try {
  const candidateFiles = run("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    capture: true,
    encoding: "utf8",
  }).trim().split("\n").filter(Boolean);
  assert(candidateFiles.includes("dist/index.js"), "Git candidate is missing the Pi extension output");
  assert(candidateFiles.includes("dist/api.js"), "Git candidate is missing the public API output");

  if (process.env.CI) {
    const trackedDist = run("git", ["ls-files", "dist"], { capture: true, encoding: "utf8" })
      .trim().split("\n").filter(Boolean);
    assert(trackedDist.includes("dist/index.js"), "CI requires committed dist output for Git installs");
    assert(trackedDist.includes("dist/api.js"), "CI requires the committed public API output");
    const distStatus = run("git", ["status", "--porcelain", "--untracked-files=all", "--", "dist"], {
      capture: true,
      encoding: "utf8",
    }).trim();
    assert.equal(distStatus, "", `Committed dist output is stale:\n${distStatus}`);
  }

  mkdirSync(candidatePath);
  for (const relativePath of candidateFiles) {
    const sourcePath = join(projectRoot, relativePath);
    if (!existsSync(sourcePath)) continue;
    const destinationPath = join(candidatePath, relativePath);
    mkdirSync(dirname(destinationPath), { recursive: true });
    cpSync(sourcePath, destinationPath, { dereference: false });
  }

  run("git", ["init", "--quiet", "--initial-branch=main"], { cwd: candidatePath });
  run("git", ["add", "."], { cwd: candidatePath });
  run("git", [
    "-c", "user.name=Moron Guard Smoke",
    "-c", "user.email=smoke@example.invalid",
    "commit", "--quiet", "-m", "Git install candidate",
  ], { cwd: candidatePath });
  const manifest = JSON.parse(readFileSync(join(candidatePath, "package.json"), "utf8"));
  assert.equal(manifest.scripts.prepare, undefined, "Git installs must not build with omitted dev dependencies");
  assert.equal(manifest.scripts.prepack, undefined, "Git installs must not run publish builds");
  assert.equal(manifest.scripts.prepublish, undefined, "Git installs must not run publish checks");

  mkdirSync(consumerPath);
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
  run(npmCommand, ["init", "--yes"], { cwd: consumerPath, shell: process.platform === "win32" });
  run(npmCommand, [
    "install",
    "--omit=dev",
    "--no-audit",
    "--no-fund",
    `git+${pathToFileURL(candidatePath).href}`,
  ], { cwd: consumerPath, shell: process.platform === "win32" });

  const installedPath = join(consumerPath, "node_modules/moron-guard");
  assert(existsSync(join(installedPath, "dist/index.js")), "Installed Git dependency is missing the Pi extension");
  assert(!existsSync(join(installedPath, "node_modules/typescript")), "Git dependency installed dev-only TypeScript");
  run(process.execPath, [
    "-e",
    "import('moron-guard').then(({ createGuard }) => { if (createGuard().decide('git status').action !== 'allow') process.exit(1) })",
  ], { cwd: consumerPath });

  console.log("Consumer Git dependency production install passed.");
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
