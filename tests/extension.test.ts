import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import moronGuardExtension from "../src/index.ts";

type CapturedHook = (event: unknown, context: unknown) => Promise<unknown>;
type CapturedCommand = { handler: (args: string, context: unknown) => Promise<unknown> };

test("Pi adapter registers hooks, blocks commands, and honors session controls", async () => {
  const hooks = new Map<string, CapturedHook>();
  const commands = new Map<string, CapturedCommand>();
  const entries: Array<{ type: string; data: unknown }> = [];
  const notifications: string[] = [];
  const cwd = await mkdtemp(join(tmpdir(), "moron-extension-"));

  const pi = {
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
    on(name: string, handler: CapturedHook) {
      hooks.set(name, handler);
    },
    registerCommand(name: string, command: CapturedCommand) {
      commands.set(name, command);
    },
  } as unknown as Parameters<typeof moronGuardExtension>[0];
  const context = {
    cwd,
    hasUI: false,
    sessionManager: { getBranch: () => [] },
    ui: {
      notify: (message: string) => notifications.push(message),
      setStatus: () => undefined,
      theme: { fg: (_color: string, text: string) => text },
    },
  };

  moronGuardExtension(pi);
  assert.deepEqual([...hooks.keys()].sort(), ["session_shutdown", "session_start", "session_tree", "tool_call", "user_bash"]);
  assert(commands.has("moron"));

  await hooks.get("session_start")?.({}, context);
  const safe = await hooks.get("tool_call")?.({ toolName: "bash", input: { command: "git status" } }, context);
  assert.equal(safe, undefined);

  const secretCommand = "TOKEN=super-secret rm -rf /Users/lachlan/private";
  const blocked = await hooks.get("tool_call")?.({ toolName: "bash", input: { command: secretCommand } }, context);
  assert.equal((blocked as { block?: boolean }).block, true);
  const reason = (blocked as { reason?: string }).reason ?? "";
  assert.doesNotMatch(reason, /super-secret|\/Users\/lachlan/);
  assert.match(reason, /TOKEN=\[REDACTED\]/);

  const userBash = await hooks.get("user_bash")?.({ command: "git reset --hard HEAD", cwd }, context);
  assert.equal((userBash as { result?: { exitCode?: number } }).result?.exitCode, 1);

  const command = commands.get("moron");
  await command?.handler("off", context);
  assert.deepEqual(entries.at(-1), { type: "moron-guard-state", data: { enabled: false } });
  const disabled = await hooks.get("tool_call")?.({ toolName: "bash", input: { command: "rm -rf /" } }, context);
  assert.equal(disabled, undefined);

  await command?.handler("on", context);
  await command?.handler("doctor", context);
  assert(notifications.some((message) => message.includes("Moron Guard doctor: healthy")));
});
