import assert from "node:assert/strict";
import test from "node:test";

import {
  completeHerdrA2AArgs,
  createTeamTool,
  parseHerdrA2ACommand,
  runHerdrA2ACommand,
  runHerdrA2ASlashCommand,
} from "../src/team-command.ts";
import { A2A_SYSTEM_INSTRUCTIONS } from "../extensions/herdr-a2a.ts";

test("team command validates all roles before client I/O", async () => {
  // Break caught: parsing or validation is deferred until after the client is acquired.
  const parsed = parseHerdrA2ACommand("team --self coordinator worker reviewer");
  assert.deepEqual(parsed, {
    kind: "team",
    selfRole: "coordinator",
    roles: ["worker", "reviewer"],
  });

  for (const bad of [
    "team",
    "team Worker",
    "team worker worker",
    `team ${"x".repeat(33)}`,
    `team ${Array.from({ length: 9 }, (_, index) => `worker-${index}`).join(" ")}`,
    "team --self",
    "team --self coordinator --self reviewer worker",
    "team --unknown worker",
  ]) {
    let clientCalls = 0;
    assert.throws(() => parseHerdrA2ACommand(bad), bad);
    assert.equal(clientCalls, 0);
    await assert.rejects(
      runHerdrA2ACommand(bad, async () => {
        clientCalls += 1;
        return {};
      }),
      bad,
    );
    assert.equal(clientCalls, 0, bad);
  }
});

test("team command exposes only bounded explicitly authorized interfaces", () => {
  // Break caught: the model surface authorizes a reserved leader or more than eight panes.
  const tool = createTeamTool(async () => ({}));
  const schema = tool.parameters as {
    properties: { roles: { minItems?: number; maxItems?: number } };
  };

  assert.equal(schema.properties.roles.minItems, 1);
  assert.equal(schema.properties.roles.maxItems, 8);
  assert.doesNotMatch(JSON.stringify(tool.parameters), /reserved.*brain/i);
  assert.match(
    A2A_SYSTEM_INSTRUCTIONS,
    /only after the user explicitly (?:requests|authorizes) new panes/i,
  );
});

test("team command help and completions advertise only this task boundary", () => {
  // Break caught: the completed operations remain hidden from the shared command surface.
  assert.deepEqual(parseHerdrA2ACommand("help"), { kind: "help" });
  assert.deepEqual(parseHerdrA2ACommand(""), { kind: "help" });
  assert.deepEqual(parseHerdrA2ACommand("status"), { kind: "status" });
  assert.deepEqual(parseHerdrA2ACommand("doctor"), { kind: "doctor" });
  assert.deepEqual(parseHerdrA2ACommand("uninstall"), { kind: "uninstall", purge: false });
  assert.deepEqual(parseHerdrA2ACommand("uninstall --purge"), { kind: "uninstall", purge: true });
  assert.throws(() => parseHerdrA2ACommand("uninstall --unknown"));
  assert.deepEqual(
    completeHerdrA2AArgs(""),
    ["team", "status", "doctor", "uninstall", "help"].map((value) => ({ value, label: value })),
  );
});

test("uninstall confirms before mutation and purge requires a second stronger confirmation", async () => {
  // Break caught: cancellation or a single purge prompt reaches the destructive managed backend.
  const calls: Array<[string, Record<string, unknown>]> = [];
  const confirmations: string[] = [];
  const context = {
    signal: undefined,
    ui: {
      async confirm(_title: string, message: string) {
        confirmations.push(message);
        return true;
      },
      notify() {},
    },
  } as unknown as Parameters<typeof runHerdrA2ASlashCommand>[1];
  await runHerdrA2ASlashCommand("uninstall --purge", context, async (method, params) => {
    calls.push([method, params]);
    return { state: "removed", retained_data: false };
  });
  assert.equal(confirmations.length, 2);
  assert.match(confirmations[0]!, /retained.*unless.*purge/i);
  assert.match(confirmations[1]!, /permanently.*database|database.*permanently/i);
  assert.deepEqual(calls, [["managed_remove", { purge: true }]]);

  let canceledCalls = 0;
  const canceled = {
    ...context,
    ui: {
      confirm: async () => false,
      notify() {},
    },
  } as unknown as Parameters<typeof runHerdrA2ASlashCommand>[1];
  await runHerdrA2ASlashCommand("uninstall", canceled, async () => {
    canceledCalls += 1;
    return {};
  });
  assert.equal(canceledCalls, 0);
});

test("status and doctor call only their concrete shared backends", async () => {
  // Break caught: a slash operation is advertised but routed to team creation, task listing, or
  // another placeholder method.
  const calls: Array<[string, Record<string, unknown>]> = [];
  const callClient = async (method: string, params: Record<string, unknown>) => {
    calls.push([method, params]);
    if (method === "status") {
      return {
        workspace_id: "workspace-one",
        broker: "healthy",
        storage: "reconciled",
        registrations: 1,
        agents: [{ role: "worker", canonical_name: "worker-k7m2", status: "connected" }],
        tasks: { queued: 1, leased: 0, waiting_reply: 0, terminal: 4 },
        last_event: { kind: "registered", canonical_name: "worker-k7m2", unix_time: 1234 },
      };
    }
    return {
      overall: "healthy",
      checks: [{ code: "broker_proof_ok", state: "healthy", summary: "Broker proof is valid." }],
    };
  };

  const status = await runHerdrA2ACommand("status", callClient);
  const doctor = await runHerdrA2ACommand("doctor", callClient);
  assert.deepEqual(calls, [["status", {}], ["doctor", {}]]);
  assert.match(status.text, /workspace-one/);
  assert.match(status.text, /queued 1/);
  assert.match(doctor.text, /broker_proof_ok/);
  assert.doesNotMatch(`${status.text}\n${doctor.text}`, /private|bearer|task-[a-z0-9]/i);
});

test("status uses the shared 256-byte role contract and rejects line separators", async () => {
  const status = (role: string) => runHerdrA2ACommand("status", async () => ({
    workspace_id: "workspace-one",
    broker: "healthy",
    storage: "reconciled",
    registrations: 1,
    agents: [{ role, canonical_name: "worker-k7m2", status: "connected" }],
    tasks: { queued: 0, leased: 0, waiting_reply: 0, terminal: 0 },
    last_event: null,
  }));

  assert.match((await status("é".repeat(128))).text, /worker-k7m2/);
  await assert.rejects(status(`worker\u2028forged`), /invalid redacted Herdr status/);
  await assert.rejects(status(`worker\u2029forged`), /invalid redacted Herdr status/);
  await assert.rejects(status(`${"é".repeat(128)}x`), /invalid redacted Herdr status/);
});

test("team command rejects unsafe broker directory fields before rendering", async () => {
  // Break caught: a compromised child injects controls through a canonical name or opaque pane ID.
  await assert.rejects(
    runHerdrA2ACommand("team worker", async () => ({
      members: [{
        requested_role: "worker",
        pane_id: "opaque-pane",
        canonical_name: "worker-k7m2\nforged",
        state: "registered",
        error_code: null,
      }],
    })),
    /invalid Herdr team result/i,
  );
});

test("team slash and tool results bind exactly to authorized role order", async () => {
  // Break caught: a valid-looking missing, extra, substituted, or reordered directory is rendered.
  const member = (role: string) => ({
    requested_role: role,
    pane_id: `opaque-${role}`,
    canonical_name: `${role}-k7m2`,
    state: "registered",
    error_code: null,
  });
  const mismatches = [
    [member("worker")],
    [member("worker"), member("reviewer"), member("observer")],
    [member("worker"), member("observer")],
    [member("reviewer"), member("worker")],
  ];

  for (const members of mismatches) {
    await assert.rejects(
      runHerdrA2ACommand(
        "team worker reviewer",
        async () => ({ members }),
      ),
      /invalid Herdr team result/i,
    );
    const tool = createTeamTool(async () => ({ members }));
    await assert.rejects(
      tool.execute(
        "team-tool",
        { roles: ["worker", "reviewer"] },
        undefined,
        undefined,
        {} as never,
      ),
      /invalid Herdr team result/i,
    );
  }
});
