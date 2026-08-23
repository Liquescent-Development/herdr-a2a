import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, copyFile, mkdir, mkdtemp, realpath, rename, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import * as sessionClientModule from "../src/session-client.ts";
import {
  MAX_NDJSON_LINE_BYTES,
  SessionClient,
  SessionRequestAbortedError,
  loadRuntimeDescriptor,
  sameFileIdentity,
  startSessionClient,
  type SessionProcess,
} from "../src/session-client.ts";

interface ManagedPluginFunctions {
  isManagedPluginActive?: (options?: Record<string, unknown>) => Promise<boolean>;
  ensureWorkspaceBroker?: (options?: Record<string, unknown>) => Promise<void>;
}

test("managed plugin gate validates Herdr context and exact enabled plugin JSON", async () => {
  // Break caught: a stale shim invokes plugin/bootstrap commands outside Herdr, with unbounded
  // identities, or after the managed plugin has been removed or disabled.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.isManagedPluginActive, "function");
  if (managed.isManagedPluginActive === undefined) return;
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: "workspace-1",
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
  };
  const calls: unknown[][] = [];
  const active = await managed.isManagedPluginActive({
    env,
    runCommand: async (file: string, args: string[], options: unknown) => {
      calls.push([file, args, options]);
      return {
        stdout: JSON.stringify({
          id: "cli:plugin",
          result: {
            plugins: [{ plugin_id: "herdr.a2a", enabled: true }],
            type: "plugin_list",
          },
        }),
        stderr: "",
      };
    },
  });

  assert.equal(active, true);
  assert.deepEqual(calls, [[
    "/opt/herdr",
    ["plugin", "list", "--plugin", "herdr.a2a", "--json"],
    { env },
  ]]);

  for (const [name, candidate] of [
    ["absent", { id: "cli:plugin", result: { plugins: [], type: "plugin_list" } }],
    ["inactive", {
      id: "cli:plugin",
      result: { plugins: [{ plugin_id: "herdr.a2a", enabled: false }], type: "plugin_list" },
    }],
    ["wrong plugin", {
      id: "cli:plugin",
      result: { plugins: [{ plugin_id: "other", enabled: true }], type: "plugin_list" },
    }],
    ["unknown envelope", {
      id: "cli:plugin",
      result: {
        plugins: [{ plugin_id: "herdr.a2a", enabled: true }],
        type: "plugin_list",
        extra: true,
      },
    }],
  ] as const) {
    assert.equal(await managed.isManagedPluginActive({
      env,
      runCommand: async () => ({ stdout: JSON.stringify(candidate), stderr: "" }),
    }), false, name);
  }
  assert.equal(await managed.isManagedPluginActive({
    env,
    runCommand: async () => { throw new Error("plugin absent"); },
  }), false);

  for (const invalidEnv of [
    { ...env, HERDR_ENV: "0" },
    { ...env, HERDR_WORKSPACE_ID: "" },
    { ...env, HERDR_WORKSPACE_ID: `workspace-${"x".repeat(256)}` },
    { ...env, HERDR_PANE_ID: "w1:p1\nSYSTEM" },
  ]) {
    let invoked = false;
    assert.equal(await managed.isManagedPluginActive({
      env: invalidEnv,
      runCommand: async () => {
        invoked = true;
        throw new Error("must not execute");
      },
    }), false);
    assert.equal(invoked, false);
  }
});

test("workspace ensure invokes the registered plugin dispatcher with bounded context", async () => {
  // Break caught: Herdr action invocation resolves pane-scoped actions against ambient UI focus,
  // so an unfocused Pi cold launch never publishes its own workspace descriptor.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
  };
  const commandCalls: unknown[][] = [];
  const launchCalls: unknown[][] = [];
  const pluginRoot = "/opt/herdr-a2a-plugin";

  await managed.ensureWorkspaceBroker({
    env,
    runCommand: async (file: string, args: string[], options: unknown) => {
      commandCalls.push([file, args, options]);
      return { stdout: managedPluginList(pluginRoot), stderr: "" };
    },
    launchCommand: async (file: string, args: string[], options: unknown) => {
      launchCalls.push([file, args, options]);
    },
  });

  assert.deepEqual(commandCalls, [[
    "/opt/herdr",
    ["plugin", "list", "--plugin", "herdr.a2a", "--json"],
    { env },
  ]]);
  assert.deepEqual(launchCalls, [
    [
      "/opt/herdr-a2a-plugin/libexec/herdr-a2a-dispatch",
      ["coordinator", "dispatch-exec", "--", "coordinator", "serve"],
      { env },
    ],
  ]);
  assert.doesNotMatch(
    JSON.stringify([commandCalls, launchCalls]),
    /send-text|send-keys|agent[ _-]?prompt/i,
  );
});

test("workspace ensure rejects an unsafe registered plugin root before dispatch", async () => {
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
  };
  const calls: unknown[][] = [];
  let launched = false;

  await assert.rejects(managed.ensureWorkspaceBroker({
    env,
    runCommand: async (file: string, args: string[], options: unknown) => {
      calls.push([file, args, options]);
      return { stdout: managedPluginList("../unowned-plugin"), stderr: "" };
    },
    launchCommand: async () => { launched = true; },
  }), /registered managed Herdr A2A plugin is unavailable/);
  assert.equal(calls.length, 1, "unsafe plugin root reached native dispatch");
  assert.equal(launched, false);
});

test("workspace ensure derives and forwards required native dispatch environment", async () => {
  // Break caught: ordinary Pi panes expose the Herdr socket/workspace identity but do not set
  // HERDR_BIN_PATH, while authenticated native dispatch requires that exact absolute executable.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  const binDir = await mkdtemp(join(tmpdir(), "herdr-a2a-herdr-bin-"));
  const herdr = join(binDir, "herdr");
  await writeFile(herdr, "fixture");
  await chmod(herdr, 0o700);
  const canonicalHerdr = await realpath(herdr);
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
    PATH: binDir,
    HOME: "/Users/tester",
  };
  const commandCalls: unknown[][] = [];
  const launchCalls: unknown[][] = [];

  await managed.ensureWorkspaceBroker({
    env,
    runCommand: async (file: string, args: string[], options: unknown) => {
      commandCalls.push([file, args, options]);
      return { stdout: managedPluginList("/opt/herdr-a2a-plugin"), stderr: "" };
    },
    launchCommand: async (file: string, args: string[], options: unknown) => {
      launchCalls.push([file, args, options]);
    },
  });

  assert.equal(commandCalls[0]?.[0], canonicalHerdr);
  assert.deepEqual(launchCalls[0]?.[2], {
    env: {
      ...env,
      HERDR_BIN_PATH: canonicalHerdr,
      HERDR_PLUGIN_STATE_DIR: "/Users/tester/.local/state/herdr/plugins/herdr.a2a",
    },
  });
});

test("workspace ensure waits for delayed authenticated descriptor publication", async () => {
  // Break caught: Herdr action completion races descriptor publication, so cold Pi startup
  // reports unavailable and remains absent until an unrelated A2A tool call retries acquisition.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  await unlink(fixture.descriptorPath);
  let published = false;
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
  };

  await managed.ensureWorkspaceBroker({
    env,
    descriptorReadyTimeoutMs: 1_000,
    descriptorRetryDelayMs: 5,
    runCommand: async () => ({
      stdout: managedPluginList("/opt/herdr-a2a-plugin"),
      stderr: "",
    }),
    launchCommand: async () => {
      setImmediate(() => {
        void writeDescriptor(fixture).then(() => { published = true; });
      });
    },
  });

  assert.equal(published, true, "ensure returned before authenticated descriptor publication");
  assert.equal((await loadRuntimeDescriptor({ env })).workspace_id, fixture.workspaceId);
});

test("default workspace ensure covers the native ten-second launch window", { timeout: 7_000 }, async () => {
  // Break caught: JavaScript abandons broker acquisition at five seconds even though the native
  // coordinator is contractually allowed ten seconds to publish its authenticated descriptor.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  await unlink(fixture.descriptorPath);
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
  };
  let publisher: NodeJS.Timeout | undefined;
  try {
    await managed.ensureWorkspaceBroker({
      env,
      descriptorRetryDelayMs: 10,
      runCommand: async () => ({
        stdout: managedPluginList("/opt/herdr-a2a-plugin"),
        stderr: "",
      }),
      launchCommand: async () => {
        publisher = setTimeout(() => { void writeDescriptor(fixture); }, 5_100);
      },
    });
  } finally {
    if (publisher !== undefined) clearTimeout(publisher);
  }

  assert.equal((await loadRuntimeDescriptor({ env })).workspace_id, fixture.workspaceId);
});

test("workspace ensure fails closed at the descriptor readiness deadline", async () => {
  // Break caught: a missing or invalid descriptor leaves cold Pi startup waiting forever or
  // reports success without an authenticated broker endpoint.
  const managed = sessionClientModule as ManagedPluginFunctions;
  assert.equal(typeof managed.ensureWorkspaceBroker, "function");
  if (managed.ensureWorkspaceBroker === undefined) return;
  const fixture = await descriptorFixture();
  await unlink(fixture.descriptorPath);
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_BIN_PATH: "/opt/herdr",
    HERDR_PLUGIN_STATE_DIR: "/opt/herdr-a2a-state",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    XDG_RUNTIME_DIR: fixture.base,
  };

  await assert.rejects(managed.ensureWorkspaceBroker({
    env,
    descriptorReadyTimeoutMs: 10,
    descriptorRetryDelayMs: 2,
    runCommand: async () => ({
      stdout: managedPluginList("/opt/herdr-a2a-plugin"),
      stderr: "",
    }),
    launchCommand: async () => {},
  }), /authenticated runtime descriptor was not published before the readiness deadline/);
});

test("workspace ensure honors a pre-aborted caller before any external command", async () => {
  // Break caught: a canceled Pi tool continues broker discovery/launch during lazy reacquisition.
  const controller = new AbortController();
  controller.abort();
  let commands = 0;
  let launches = 0;

  await assert.rejects(sessionClientModule.ensureWorkspaceBroker({
    signal: controller.signal,
    runCommand: async () => {
      commands += 1;
      throw new Error("canceled ensure invoked Herdr");
    },
    launchCommand: async () => { launches += 1; },
  }), /broker ensure aborted/);
  assert.equal(commands, 0);
  assert.equal(launches, 0);
});

function managedPluginList(pluginRoot: string): string {
  return JSON.stringify({
    id: "cli:plugin",
    result: {
      plugins: [{
        plugin_id: "herdr.a2a",
        enabled: true,
        plugin_root: pluginRoot,
      }],
      type: "plugin_list",
    },
  });
}

test("loads only the workspace-scoped descriptor for a shared Herdr socket", async () => {
  // Break caught: Pi derives discovery from only the socket session and either misses scoped
  // descriptors or adopts another workspace's credentials.
  const base = await mkdtemp(join(tmpdir(), "herdr-a2a-pi-workspace-"));
  await chmod(base, 0o700);
  const runtimeRoot = join(base, "herdr-a2a");
  await mkdir(runtimeRoot, { mode: 0o700 });
  const socketPath = join(base, "herdr.sock");
  const sessionKey = createHash("sha256").update(socketPath).digest("hex");
  const executablePath = await realpath(process.execPath);
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  for (const workspaceId of ["workspace-left", "workspace-right"]) {
    const scopeKey = createHash("sha256")
      .update(sessionKey)
      .update("\0")
      .update(workspaceId)
      .digest("hex");
    const descriptorPath = join(runtimeRoot, `${scopeKey}.json`);
    await writeFile(descriptorPath, JSON.stringify({
      session_key: sessionKey,
      workspace_id: workspaceId,
      base_url: workspaceId === "workspace-left"
        ? "http://127.0.0.1:43121"
        : "http://127.0.0.1:43122",
      bearer_token: Buffer.alloc(32, workspaceId.length).toString("base64url"),
      broker_instance_id: Buffer.alloc(32, workspaceId.length + 1).toString("base64url"),
      executable_path: executablePath,
      broker_pid: process.pid,
      created_unix_ms: Date.now(),
    }), { mode: 0o600 });
    await chmod(descriptorPath, 0o600);
  }

  const left = await loadRuntimeDescriptor({
    env: {
      HERDR_SOCKET_PATH: socketPath,
      HERDR_WORKSPACE_ID: "workspace-left",
      TMPDIR: base,
    },
    platform: "darwin",
    uid: process.getuid(),
  });
  const right = await loadRuntimeDescriptor({
    env: {
      HERDR_SOCKET_PATH: socketPath,
      HERDR_WORKSPACE_ID: "workspace-right",
      TMPDIR: base,
    },
    platform: "darwin",
    uid: process.getuid(),
  });

  assert.equal(left.workspace_id, "workspace-left");
  assert.equal(right.workspace_id, "workspace-right");
  assert.notEqual(left.bearer_token, right.bearer_token);
});

test("rejects missing or unsafe Herdr workspace IDs before descriptor I/O", async () => {
  // Break caught: absent, control-bearing, or unbounded workspace identity reaches legacy or
  // ambiguous descriptor discovery instead of failing before filesystem access.
  const socketPath = "/tmp/herdr.sock";
  for (const workspaceId of [undefined, "", "workspace\0other", "workspace\nother", "w".repeat(257)]) {
    await assert.rejects(loadRuntimeDescriptor({
      env: {
        HERDR_SOCKET_PATH: socketPath,
        HERDR_WORKSPACE_ID: workspaceId,
        TMPDIR: "/tmp/descriptor/must/not/be/read",
      },
      platform: "darwin",
      uid: 1,
    }), /HERDR_WORKSPACE_ID/);
  }
});

class FakeSessionProcess extends EventEmitter implements SessionProcess {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly writes: string[] = [];
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killCount = 0;
  readonly killSignals: Array<NodeJS.Signals | number | undefined> = [];
  autoTerminate = true;
  killResult = true;
  terminateOn: NodeJS.Signals = "SIGTERM";

  constructor() {
    super();
    this.stdin.setEncoding("utf8");
    this.stdin.on("data", (chunk: string) => this.writes.push(chunk));
  }

  kill(signal?: NodeJS.Signals | number): boolean {
    this.killCount += 1;
    this.killSignals.push(signal);
    if (this.killResult && this.autoTerminate && signal === this.terminateOn) {
      queueMicrotask(() => this.emitExit(null, signal));
    }
    return this.killResult;
  }

  respond(value: unknown): void {
    this.stdout.write(`${JSON.stringify(value)}\n`);
  }

  emitExit(code: number | null, signal: NodeJS.Signals | null): void {
    this.exitCode = code;
    this.signalCode = signal;
    this.emit("exit", code, signal);
    queueMicrotask(() => this.emit("close", code, signal));
  }
}

test("matches chunked, out-of-order response lines to request promises", async () => {
  // Break caught: resolving by arrival order instead of the NDJSON correlation ID.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);

  const first = client.call("list_agents", {});
  const second = client.call("wait_for_message", {});
  const secondLine = JSON.stringify({ id: "2", result: { task_id: "task-2" } });
  process.stdout.write(secondLine.slice(0, 11));
  process.stdout.write(`${secondLine.slice(11)}\n${JSON.stringify({ id: "1", result: { agents: [] } })}\n`);

  assert.deepEqual(await first, { agents: [] });
  assert.deepEqual(await second, { task_id: "task-2" });
  assert.deepEqual(process.writes, [
    '{"id":"1","method":"list_agents","params":{}}\n',
    '{"id":"2","method":"wait_for_message","params":{}}\n',
  ]);
});

test("preserves confirmed and unconfirmed restart timeout results from the child", async () => {
  // Break caught: NDJSON handling drops or rewrites recovery identity before the Pi extension sees it.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const unconfirmed = client.call("send_message", { agent: "reviewer", text: "review" });
  const confirmed = client.call("send_message", { agent: "reviewer", resume_task_id: "task-confirmed" });
  const unconfirmedResult = {
    agent: "reviewer",
    task_id: "task-unconfirmed",
    conversation_id: null,
    resume_task_id: "task-unconfirmed",
    state: "unknown",
    timed_out: true,
    task_confirmed: false,
    task_reachable: false,
    recovery_reason: "broker_unavailable",
  };
  const confirmedResult = {
    agent: "reviewer",
    task_id: "task-confirmed",
    conversation_id: "conversation-confirmed",
    resume_task_id: "task-confirmed",
    state: "working",
    timed_out: true,
    task_confirmed: true,
    task_reachable: true,
    recovery_reason: "deadline_expired",
  };

  process.respond({ id: "2", result: confirmedResult });
  process.respond({ id: "1", result: unconfirmedResult });

  assert.deepEqual(await unconfirmed, unconfirmedResult);
  assert.deepEqual(await confirmed, confirmedResult);
  assert.deepEqual(process.writes, [
    '{"id":"1","method":"send_message","params":{"agent":"reviewer","text":"review"}}\n',
    '{"id":"2","method":"send_message","params":{"agent":"reviewer","resume_task_id":"task-confirmed"}}\n',
  ]);
});

test("rejects every pending request when the child exits and bounds stderr context", async () => {
  // Break caught: a dead child leaves one or more tool executions hung forever.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const first = client.call("list_agents", {});
  const second = client.call("wait_for_message", {});
  process.stderr.write(`discarded:${"x".repeat(80 * 1024)}:useful-tail`);

  process.emit("exit", 7, null);

  await assert.rejects(first, (error: Error) => {
    assert.match(error.message, /client session exited with code 7/);
    assert.match(error.message, /useful-tail/);
    assert.ok(error.message.length < 70 * 1024);
    return true;
  });
  await assert.rejects(second, /client session exited with code 7/);
});

test("a malformed or oversized response is a fatal protocol error", async () => {
  // Break caught: corrupt stdout is ignored while pending calls remain unresolved.
  for (const response of ["not-json\n", `${"x".repeat(MAX_NDJSON_LINE_BYTES + 1)}\n`]) {
    const process = new FakeSessionProcess();
    const client = new SessionClient(process);
    const pending = client.call("list_agents", {});

    process.stdout.write(response);

    await assert.rejects(pending, /client session protocol error/);
    assert.equal(process.killCount, 1);
  }
});

test("malformed UTF-8 is a fatal protocol error", async () => {
  // Break caught: replacement decoding turns corrupt peer bytes into a successful response.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const pending = client.call("list_agents", {});
  process.stdout.write(Buffer.concat([
    Buffer.from('{"id":"1","result":"'),
    Buffer.from([0xff]),
    Buffer.from('"}\n'),
  ]));

  await assert.rejects(pending, /client session protocol error: response is not valid UTF-8/);
  assert.equal(process.killCount, 1);
});

test("a malformed correlated error rejects the matched request with the protocol failure", { timeout: 250 }, async () => {
  // Break caught: deleting the matched request before validating its error leaves it hung.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const pending = client.call("list_agents", {});

  process.respond({ id: "1", error: { code: 7, message: "wrong code type" } });

  await assert.rejects(pending, /client session protocol error: response error has an invalid shape/);
});

test("typed session errors preserve exact sorted ambiguity candidates", async () => {
  // Break caught: the native client emits canonical candidates but the Pi transport replaces the
  // structured error with a plain code/message Error that cannot guide a canonical retry.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const pending = client.call("send_message", { agent: "reviewer" });
  process.respond({
    id: "1",
    error: {
      code: "ambiguous_agent",
      message: "multiple live agents have this role",
      details: { candidates: ["reviewer-a1", "reviewer-b2"] },
    },
  });

  await assert.rejects(pending, (error: Error & {
    code?: unknown;
    details?: unknown;
  }) => {
    assert.equal(error.constructor.name, "SessionRequestError");
    assert.equal(error.code, "ambiguous_agent");
    assert.deepEqual(error.details, { candidates: ["reviewer-a1", "reviewer-b2"] });
    assert.match(error.message, /reviewer-a1, reviewer-b2/);
    return true;
  });
});

test("request cancellation rejects every shared pending call with a structured source", async () => {
  // Break caught: the extension cannot distinguish the pump's collateral client-wide rejection
  // from an abort of the pump's own controller and therefore permanently stops automatic receive.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const pumpWait = client.call("wait_for_message", { timeout_ms: 86_400_000 });
  const controller = new AbortController();
  const ordinaryCall = client.call("list_agents", {}, controller.signal);

  controller.abort();
  const outcomes = await Promise.allSettled([ordinaryCall, pumpWait]);

  assert.deepEqual(outcomes.map((outcome) => outcome.status), ["rejected", "rejected"]);
  const ordinaryError = outcomes[0]?.status === "rejected" ? outcomes[0].reason : undefined;
  const pumpError = outcomes[1]?.status === "rejected" ? outcomes[1].reason : undefined;
  assert.ok(ordinaryError instanceof SessionRequestAbortedError);
  assert.ok(pumpError instanceof SessionRequestAbortedError);
  assert.equal(ordinaryError.source, "request-signal");
  assert.equal(pumpError, ordinaryError);
  await client.close();
});

test("close is idempotent, kills the child once, and rejects pending work", async () => {
  // Break caught: repeated shutdown hooks signal the child repeatedly or leak a call.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const pending = client.call("wait_for_message", {});

  await Promise.all([client.close(), client.close()]);

  await assert.rejects(pending, /client session closed/);
  await assert.rejects(client.call("list_agents", {}), /client session closed/);
  assert.equal(process.killCount, 1);
});

test("close waits for process close and is shared by concurrent callers", async () => {
  // Break caught: retirement resolves after signaling while the old child is still live.
  const process = new FakeSessionProcess();
  process.autoTerminate = false;
  const client = new SessionClient(process, { termGraceMs: 50, killGraceMs: 50 });
  let settled = false;

  const retirement = client.close();
  const second = client.close();
  assert.equal(retirement, second);
  const first = retirement.then(() => { settled = true; });
  await Promise.resolve();
  assert.deepEqual(process.killSignals, ["SIGTERM"]);
  assert.equal(process.stdin.writableEnded, true);
  assert.equal(settled, false);
  process.exitCode = 0;
  process.emit("exit", 0, null);
  await Promise.resolve();
  assert.equal(settled, false);
  process.emit("close", 0, null);

  await Promise.all([first, second]);
  assert.equal(settled, true);
});

test("close called after exit still waits for the process close event", async () => {
  // Break caught: an exit observed just before shutdown was mistaken for fully closed stdio.
  const process = new FakeSessionProcess();
  process.autoTerminate = false;
  const client = new SessionClient(process, { termGraceMs: 50, killGraceMs: 50 });
  process.exitCode = 0;
  process.emit("exit", 0, null);
  let settled = false;

  const retirement = client.close().then(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false);
  process.emit("close", 0, null);

  await retirement;
  assert.equal(settled, true);
});

test("close escalates to SIGKILL after a bounded TERM grace", async () => {
  // Break caught: a child ignoring SIGTERM makes shutdown hang or survives replacement.
  const process = new FakeSessionProcess();
  process.terminateOn = "SIGKILL";
  const client = new SessionClient(process, { termGraceMs: 5, killGraceMs: 25 });

  await client.close();

  assert.deepEqual(process.killSignals, ["SIGTERM", "SIGKILL"]);
  assert.equal(process.signalCode, "SIGKILL");
});

test("close handles an already-exited child and rejects boundedly when signals fail", async () => {
  // Break caught: kill(false) is mistaken for successful retirement or waits forever.
  const exited = new FakeSessionProcess();
  exited.exitCode = 0;
  const exitedClient = new SessionClient(exited, { termGraceMs: 5, killGraceMs: 5 });
  await exitedClient.close();
  assert.deepEqual(exited.killSignals, []);

  const stuck = new FakeSessionProcess();
  stuck.autoTerminate = false;
  stuck.killResult = false;
  const stuckClient = new SessionClient(stuck, { termGraceMs: 5, killGraceMs: 5 });
  await assert.rejects(stuckClient.close(), /could not be terminated/);
  assert.deepEqual(stuck.killSignals, ["SIGTERM", "SIGKILL"]);
});

test("close retires an actual subprocess before resolving", { timeout: 2_000 }, async () => {
  // Break caught: fake-only lifecycle behavior misses Node ChildProcess event ordering.
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const client = new SessionClient(child, { termGraceMs: 100, killGraceMs: 500 });

  await client.close();

  assert.ok(child.exitCode !== null || child.signalCode !== null);
});

test("an already-aborted call is not written and a mid-call abort terminates all pending work", { timeout: 250 }, async () => {
  // Break caught: Pi aborts a tool while an indefinite broker wait keeps its turn/session hung.
  const process = new FakeSessionProcess();
  const client = new SessionClient(process);
  const alreadyAborted = new AbortController();
  alreadyAborted.abort();

  await assert.rejects(client.call("wait_for_message", {}, alreadyAborted.signal), /request aborted/);
  assert.deepEqual(process.writes, []);

  const controller = new AbortController();
  const wait = client.call("wait_for_message", {}, controller.signal);
  const concurrent = client.call("list_agents", {});
  controller.abort();

  await assert.rejects(wait, /request aborted/);
  await assert.rejects(concurrent, /request aborted/);
  assert.equal(process.killCount, 1);
});

test("every stdio failure rejects pending work and terminates the child", async () => {
  // Break caught: an unhandled pipe error crashes Pi or leaves tool promises unresolved.
  for (const stream of ["stdin", "stdout", "stderr"] as const) {
    const process = new FakeSessionProcess();
    const client = new SessionClient(process);
    const pending = client.call("list_agents", {});

    process[stream].emit("error", new Error(`${stream} broke`));

    await assert.rejects(pending, new RegExp(`client session ${stream} error: ${stream} broke`));
    assert.equal(process.killCount, 1);
  }
});

test("unexpected stdout termination rejects pending work", async () => {
  // Break caught: stdout can close without a child exit event and strand all correlations.
  for (const event of ["end", "close"] as const) {
    const process = new FakeSessionProcess();
    const client = new SessionClient(process);
    const pending = client.call("wait_for_message", {});

    process.stdout.emit(event);

    await assert.rejects(pending, /client session stdout ended unexpectedly/);
    assert.equal(process.killCount, 1);
  }
});

test("starts the descriptor executable with the Pi session ID after permission checks", async () => {
  // Break caught: PATH lookup or a caller-provided executable bypasses the protected descriptor.
  const base = await mkdtemp(join(tmpdir(), "herdr-a2a-pi-test-"));
  const runtimeRoot = join(base, "herdr-a2a");
  await mkdir(runtimeRoot, { mode: 0o700 });
  await chmod(runtimeRoot, 0o700);
  const socketPath = join(base, "herdr.sock");
  const sessionKey = createHash("sha256").update(socketPath).digest("hex");
  const workspaceId = "test-workspace";
  const scopeKey = createHash("sha256")
    .update(sessionKey)
    .update("\0")
    .update(workspaceId)
    .digest("hex");
  const executablePath = await realpath(process.execPath);
  const descriptorPath = join(runtimeRoot, `${scopeKey}.json`);
  await writeFile(
    descriptorPath,
    JSON.stringify({
      session_key: sessionKey,
      workspace_id: workspaceId,
      base_url: "http://127.0.0.1:12345",
      bearer_token: Buffer.alloc(32, 7).toString("base64url"),
      broker_instance_id: Buffer.alloc(32, 11).toString("base64url"),
      executable_path: executablePath,
      broker_pid: process.pid,
      created_unix_ms: Date.now(),
    }),
    { mode: 0o600 },
  );
  await chmod(descriptorPath, 0o600);
  const child = new FakeSessionProcess();
  const invocations: unknown[][] = [];
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  const client = await startSessionClient("pi-session-123", {
    env: {
      HERDR_SOCKET_PATH: socketPath,
      HERDR_WORKSPACE_ID: workspaceId,
      TMPDIR: base,
    },
    platform: "darwin",
    uid: process.getuid(),
    spawn: (file, args, options) => {
      invocations.push([file, args, options]);
      queueMicrotask(() => child.respond({ id: "1", result: { agents: [] } }));
      return child;
    },
  });

  assert.deepEqual(invocations, [[
    executablePath,
    ["client-session", "--harness-session-id", "pi-session-123"],
    {
      env: {
        HERDR_SOCKET_PATH: socketPath,
        HERDR_WORKSPACE_ID: workspaceId,
        TMPDIR: base,
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  ]]);
  await client.close();
});

test("managed client session derives required native environment from an ordinary Pi pane", async () => {
  // Break caught: cold broker startup succeeded, but the first team/tool request launched the
  // native client without HERDR_BIN_PATH or HERDR_PLUGIN_STATE_DIR and failed before registration.
  const fixture = await descriptorFixture();
  const binDir = await mkdtemp(join(tmpdir(), "herdr-a2a-client-herdr-bin-"));
  const herdr = join(binDir, "herdr");
  await writeFile(herdr, "fixture");
  await chmod(herdr, 0o700);
  const canonicalHerdr = await realpath(herdr);
  const child = new FakeSessionProcess();
  const invocations: unknown[][] = [];
  const env = {
    HERDR_ENV: "1",
    HERDR_WORKSPACE_ID: fixture.workspaceId,
    HERDR_PANE_ID: "w1:p1",
    HERDR_SOCKET_PATH: fixture.socketPath,
    TMPDIR: fixture.base,
    PATH: binDir,
    HOME: "/Users/tester",
  };
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  const client = await startSessionClient("pi-session-managed", {
    env,
    platform: "darwin",
    uid: process.getuid(),
    spawn: (file, args, options) => {
      invocations.push([file, args, options]);
      queueMicrotask(() => child.respond({ id: "1", result: { agents: [] } }));
      return child;
    },
  });

  assert.deepEqual(invocations[0]?.[2], {
    env: {
      ...env,
      HERDR_BIN_PATH: canonicalHerdr,
      HERDR_PLUGIN_STATE_DIR: "/Users/tester/.local/state/herdr/plugins/herdr.a2a",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  await client.close();
});

interface DescriptorFixture {
  base: string;
  runtimeRoot: string;
  descriptorPath: string;
  socketPath: string;
  workspaceId: string;
  descriptor: {
    session_key: string;
    workspace_id: string;
    base_url: string;
    bearer_token: string;
    broker_instance_id: string;
    executable_path: string;
    broker_pid: number;
    created_unix_ms: number;
  };
}

async function descriptorFixture(): Promise<DescriptorFixture> {
  const base = await mkdtemp(join(tmpdir(), "herdr-a2a-pi-descriptor-"));
  await chmod(base, 0o700);
  const runtimeRoot = join(base, "herdr-a2a");
  await mkdir(runtimeRoot, { mode: 0o700 });
  await chmod(runtimeRoot, 0o700);
  const socketPath = join(base, "herdr.sock");
  const sessionKey = createHash("sha256").update(socketPath).digest("hex");
  const workspaceId = "test-workspace";
  const scopeKey = createHash("sha256")
    .update(sessionKey)
    .update("\0")
    .update(workspaceId)
    .digest("hex");
  const descriptorPath = join(runtimeRoot, `${scopeKey}.json`);
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
  const descriptor = {
    session_key: sessionKey,
    workspace_id: workspaceId,
    base_url: "http://127.0.0.1:43123",
    bearer_token: Buffer.alloc(32, 19).toString("base64url"),
    broker_instance_id: Buffer.alloc(32, 23).toString("base64url"),
    executable_path: await realpath(process.execPath),
    broker_pid: process.pid,
    created_unix_ms: Date.now(),
  };
  await writeFile(descriptorPath, JSON.stringify(descriptor), { mode: 0o600 });
  await chmod(descriptorPath, 0o600);
  return { base, runtimeRoot, descriptorPath, socketPath, workspaceId, descriptor };
}

async function writeDescriptor(fixture: DescriptorFixture): Promise<void> {
  await writeFile(fixture.descriptorPath, JSON.stringify(fixture.descriptor), { mode: 0o600 });
  await chmod(fixture.descriptorPath, 0o600);
}

async function expectDescriptorRejected(
  fixture: DescriptorFixture,
  pattern: RegExp,
  expectedUid?: number,
): Promise<void> {
  let spawns = 0;
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
  await assert.rejects(startSessionClient("pi-session", {
    env: {
      HERDR_SOCKET_PATH: fixture.socketPath,
      HERDR_WORKSPACE_ID: fixture.workspaceId,
      TMPDIR: fixture.base,
    },
    platform: "darwin",
    uid: expectedUid ?? process.getuid(),
    spawn: () => {
      spawns += 1;
      return new FakeSessionProcess();
    },
  }), pattern);
  assert.equal(spawns, 0);
}

test("rejects descriptor fields outside the Rust runtime contract before spawn", async () => {
  // Break caught: adapter accepts a descriptor that the supervised Rust child rejects later.
  const cases: Array<[string, (fixture: DescriptorFixture) => void]> = [
    ["session identity", (fixture) => { fixture.descriptor.session_key = "wrong"; }],
    ["workspace identity", (fixture) => { fixture.descriptor.workspace_id = "wrong"; }],
    ["loopback origin", (fixture) => { fixture.descriptor.base_url = "http://192.0.2.10:43123"; }],
    ["canonical origin", (fixture) => { fixture.descriptor.base_url = "http://127.0.0.1:04312"; }],
    ["token encoding", (fixture) => { fixture.descriptor.bearer_token = "not-base64url"; }],
    ["token padding", (fixture) => { fixture.descriptor.bearer_token = `${Buffer.alloc(32).toString("base64url")}=`; }],
    ["token length", (fixture) => { fixture.descriptor.bearer_token = Buffer.alloc(31).toString("base64url"); }],
    ["missing instance", (fixture) => {
      delete (fixture.descriptor as Partial<DescriptorFixture["descriptor"]>).broker_instance_id;
    }],
    ["empty instance", (fixture) => { fixture.descriptor.broker_instance_id = ""; }],
    ["instance padding", (fixture) => {
      fixture.descriptor.broker_instance_id = `${Buffer.alloc(32).toString("base64url")}=`;
    }],
    ["instance encoding", (fixture) => { fixture.descriptor.broker_instance_id = "not-base64url!"; }],
    ["short instance", (fixture) => {
      fixture.descriptor.broker_instance_id = Buffer.alloc(31).toString("base64url");
    }],
    ["long instance", (fixture) => {
      fixture.descriptor.broker_instance_id = Buffer.alloc(33).toString("base64url");
    }],
    ["PID zero", (fixture) => { fixture.descriptor.broker_pid = 0; }],
    ["PID negative", (fixture) => { fixture.descriptor.broker_pid = -1; }],
    ["PID fractional", (fixture) => { fixture.descriptor.broker_pid = 1.5; }],
    ["PID range", (fixture) => { fixture.descriptor.broker_pid = 2_147_483_648; }],
    ["timestamp zero", (fixture) => { fixture.descriptor.created_unix_ms = 0; }],
    ["timestamp fractional", (fixture) => { fixture.descriptor.created_unix_ms = 1.5; }],
    ["future timestamp", (fixture) => { fixture.descriptor.created_unix_ms = Date.now() + 600_000; }],
  ];
  for (const [name, mutate] of cases) {
    const fixture = await descriptorFixture();
    mutate(fixture);
    await writeDescriptor(fixture);
    await expectDescriptorRejected(fixture, /runtime descriptor/).catch((error) => {
      throw new Error(`${name}: ${error instanceof Error ? error.message : String(error)}`);
    });
  }
});

test("rejects unsafe parent, root, descriptor, and executable paths before spawn", async () => {
  // Break caught: pathname reopening weakens cross-UID/mode/symlink protections or effective X_OK.
  const parentMode = await descriptorFixture();
  await chmod(parentMode.base, 0o777);
  await expectDescriptorRejected(parentMode, /parent.*permissions/i);

  const rootMode = await descriptorFixture();
  await chmod(rootMode.runtimeRoot, 0o755);
  await expectDescriptorRejected(rootMode, /directory permissions/i);

  const wrongOwner = await descriptorFixture();
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
  await expectDescriptorRejected(wrongOwner, /wrong owner/i, process.getuid() + 1);

  const descriptorMode = await descriptorFixture();
  await chmod(descriptorMode.descriptorPath, 0o644);
  await expectDescriptorRejected(descriptorMode, /file permissions/i);

  const descriptorLink = await descriptorFixture();
  const realDescriptor = `${descriptorLink.descriptorPath}.real`;
  await rename(descriptorLink.descriptorPath, realDescriptor);
  await symlink(realDescriptor, descriptorLink.descriptorPath);
  await expectDescriptorRejected(descriptorLink, /unsafe|symbolic/i);

  const nonExecutable = await descriptorFixture();
  const executableCopy = join(nonExecutable.base, "not-owner-executable");
  await copyFile(process.execPath, executableCopy);
  await chmod(executableCopy, 0o001);
  nonExecutable.descriptor.executable_path = await realpath(executableCopy);
  await writeDescriptor(nonExecutable);
  await expectDescriptorRejected(nonExecutable, /not executable/i);

  const executableLink = await descriptorFixture();
  const linkedExecutable = join(executableLink.base, "node-link");
  await symlink(executableLink.descriptor.executable_path, linkedExecutable);
  executableLink.descriptor.executable_path = linkedExecutable;
  await writeDescriptor(executableLink);
  await expectDescriptorRejected(executableLink, /canonical/i);
});

test("rejects an executable with no mode bits even when effective access is permitted", async () => {
  // Break caught: dropping Rust's explicit 0o111 gate lets an access-only check accept the descriptor.
  const fixture = await descriptorFixture();
  const executableCopy = join(fixture.base, "mode-zero-executable");
  await copyFile(process.execPath, executableCopy);
  await chmod(executableCopy, 0o000);
  fixture.descriptor.executable_path = await realpath(executableCopy);
  await writeDescriptor(fixture);
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
  let effectiveAccessChecks = 0;
  let spawns = 0;

  await assert.rejects(startSessionClient("pi-session", {
    env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
    platform: "darwin",
    uid: process.getuid(),
    checkExecutableAccess: async () => { effectiveAccessChecks += 1; },
    spawn: () => {
      spawns += 1;
      return new FakeSessionProcess();
    },
  }), /not executable/i);

  assert.equal(effectiveAccessChecks, 1);
  assert.equal(spawns, 0);
});

test("startup waits for readiness and retires an early-exiting child", async () => {
  // Break caught: session_start caches a child that has not completed registration/readiness.
  const fixture = await descriptorFixture();
  const child = new FakeSessionProcess();
  child.autoTerminate = false;
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  const started = startSessionClient("pi-session", {
    env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
    platform: "darwin",
    uid: process.getuid(),
    spawn: () => {
      queueMicrotask(() => child.emitExit(1, null));
      return child;
    },
  });

  await assert.rejects(started, /client session exited with code 1/);
  assert.ok(child.exitCode !== null || child.signalCode !== null);
});

test("startup rejects a valid readiness reply followed by immediate child exit", async () => {
  // Break caught: a terminal child is cached because its readiness result won the promise race.
  const fixture = await descriptorFixture();
  const child = new FakeSessionProcess();
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  const started = startSessionClient("pi-session", {
    env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
    platform: "darwin",
    uid: process.getuid(),
    spawn: () => {
      queueMicrotask(() => {
        child.respond({ id: "1", result: { agents: [] } });
        child.emitExit(0, null);
      });
      return child;
    },
  });

  await assert.rejects(started, /exited during readiness/);
});

test("startup rejects a valid readiness reply followed by next-turn child exit", async () => {
  // Break caught: readiness returns and caches a child whose queued exit fires in the check phase.
  const fixture = await descriptorFixture();
  const child = new FakeSessionProcess();
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");

  const started = startSessionClient("pi-session", {
    env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
    platform: "darwin",
    uid: process.getuid(),
    spawn: () => {
      queueMicrotask(() => {
        child.respond({ id: "1", result: { agents: [] } });
        setImmediate(() => child.emitExit(0, null));
      });
      return child;
    },
  });

  await assert.rejects(started, /exited during readiness/);
});

test("startup cancellation retires a child still waiting for registration readiness", async () => {
  // Break caught: client reacquisition forwards cancellation only through broker ensure, leaving
  // the native child and its readiness request alive until the independent timeout.
  const fixture = await descriptorFixture();
  const child = new FakeSessionProcess();
  const controller = new AbortController();
  if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
  const started = startSessionClient("process-incarnation", {
    env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
    platform: "darwin",
    uid: process.getuid(),
    signal: controller.signal,
    readinessTimeoutMs: 25,
    spawn: () => {
      queueMicrotask(() => controller.abort());
      return child;
    },
  });

  await assert.rejects(started, /client session startup aborted/);
  assert.ok(child.exitCode !== null || child.signalCode !== null);
});

test("file identity comparison preserves device and inode bits above Number.MAX_SAFE_INTEGER", () => {
  // Break caught: numeric stat coercion aliases distinct 64-bit filesystem identities.
  const high = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
  assert.equal(
    sameFileIdentity({ dev: high, ino: high }, { dev: high + 1n, ino: high }),
    false,
  );
  assert.equal(
    sameFileIdentity({ dev: high, ino: high }, { dev: high, ino: high }),
    true,
  );
});

test("startup observes spawn errors and bounded readiness timeout before returning", { timeout: 500 }, async () => {
  // Break caught: session_start caches or waits forever on a child that never becomes ready.
  for (const failure of ["spawn-error", "readiness-timeout"] as const) {
    const fixture = await descriptorFixture();
    const child = new FakeSessionProcess();
    if (process.getuid === undefined) throw new Error("test requires a Unix user ID");
    const started = startSessionClient("pi-session", {
      env: { HERDR_SOCKET_PATH: fixture.socketPath, HERDR_WORKSPACE_ID: fixture.workspaceId, TMPDIR: fixture.base },
      platform: "darwin",
      uid: process.getuid(),
      readinessTimeoutMs: 5,
      spawn: () => {
        if (failure === "spawn-error") {
          queueMicrotask(() => child.emit("error", new Error("spawn ENOENT")));
        }
        return child;
      },
    });

    await assert.rejects(
      started,
      failure === "spawn-error" ? /process error: spawn ENOENT/ : /readiness timed out/,
    );
    assert.ok(child.exitCode !== null || child.signalCode !== null);
  }
});
