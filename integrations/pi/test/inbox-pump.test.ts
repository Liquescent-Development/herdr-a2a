import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  InboxPump,
  RecentInboxDeliveries,
  type InboxDelivery,
  type InboxInjectionKind,
  type InboxPumpPort,
} from "../src/inbox-pump.ts";

const DELIVERY_ID = "018f5c70-6f00-7abc-8def-0123456789ab";

test("serializes automatic deliveries until the exact task replies", async () => {
  // Break caught: a second native lease is acquired while the first peer task is still active.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("task-1"));
  await port.injected("task-1", "task");
  assert.equal(port.waitCalls, 1);

  pump.complete("other-task");
  assert.equal(port.waitCalls, 1);
  pump.complete("task-1");
  await port.waitCalled(2);
  await pump.stop();
});

test("rejects malformed inbox deliveries without injecting untrusted fields", async () => {
  // Break caught: an adapter response with an extra, oversized, or mistyped field reaches Pi.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();

  const malformed = [
    { ...delivery("task-extra"), unexpected: true },
    { ...delivery("task-text"), payload: { text: "x".repeat(64 * 1024 + 1), metadata: {}, file_refs: [] } },
    { ...delivery("task-scalar"), leased_until_unix_ms: "123" },
    { ...delivery("task-id".repeat(40)), task_id: "x".repeat(257) },
    { ...delivery("task-context"), context_id: 42 },
  ];
  for (const candidate of malformed) port.deliver(candidate);

  await port.waitCalled(malformed.length + 1);
  assert.deepEqual(port.injections, []);
  assert.deepEqual(port.replyFailures, ["task-extra", "task-text", "task-scalar", "task-context"]);
  await pump.stop();
});

test("preserves broker order and ignores duplicate completion", async () => {
  // Break caught: an old reply releases a later task or duplicate reply leases another task.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("first-task"));
  port.deliver(delivery("second-task"));
  await port.injected("first-task", "task");

  pump.complete("first-task");
  await port.injected("second-task", "task");
  pump.complete("first-task");
  assert.equal(port.waitCalls, 2);
  pump.complete("second-task");
  await port.waitCalled(3);
  await pump.stop();

  assert.deepEqual(port.injections.map(([candidate]) => candidate.task_id), ["first-task", "second-task"]);
});

test("drops exact and divergent delivery ID replays without a second injection", async () => {
  // Break caught: a valid broker envelope replay executes the same peer-authored work twice, while
  // divergent reuse of its canonical delivery ID can substitute different work on the second turn.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  const accepted = delivery("replayed-task");
  pump.start();
  try {
    port.deliver(accepted);
    await port.injected("replayed-task", "task");
    pump.complete("replayed-task");
    await port.waitCalled(2);

    port.deliver(structuredClone(accepted));
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(port.injections.map(([candidate, kind]) => [candidate.task_id, kind]), [
      ["replayed-task", "task"],
    ]);
    await port.waitCalled(3);
    await pump.settled();
    assert.equal(port.injections.length, 1);

    port.deliver({
      ...delivery("substituted-task"),
      delivery_id: accepted.delivery_id,
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(port.injections.length, 1);
    assert.deepEqual(port.replyFailures, []);
    await port.waitCalled(4);
  } finally {
    await pump.stop();
  }
});

test("retains 256 recent delivery IDs and evicts the oldest on the next acceptance", async () => {
  // Break caught: replay state is unbounded, or evicts a still-recent delivery before the declared
  // 256-ID session window has been filled.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  try {
    for (let index = 0; index < 256; index += 1) {
      const taskId = `bounded-task-${index}`;
      port.deliver(delivery(taskId));
      await port.injected(taskId, "task");
      pump.complete(taskId);
      await port.waitCalled(index + 2);
    }

    port.deliver(delivery("bounded-task-0"));
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(port.injections.length, 256);
    await port.waitCalled(258);

    port.deliver(delivery("bounded-task-256"));
    await port.injected("bounded-task-256", "task");
    pump.complete("bounded-task-256");
    await port.waitCalled(259);
    port.deliver(delivery("bounded-task-0"));
    await port.injected("bounded-task-0", "task");
    assert.equal(port.injections.length, 258);
    pump.complete("bounded-task-0");
  } finally {
    await pump.stop();
  }
});

test("shares recent delivery state across replacement pumps in one session", async () => {
  // Break caught: bounded pump failure replaces the pump object and forgets delivery IDs already
  // accepted by the same Pi session, allowing a post-recovery replay to execute again.
  const recentDeliveries = new RecentInboxDeliveries();
  const accepted = delivery("pre-replacement-task");
  const firstPort = fakePort();
  const first = new InboxPump(firstPort.value, recentDeliveries);
  first.start();
  firstPort.deliver(accepted);
  await firstPort.injected("pre-replacement-task", "task");
  first.complete("pre-replacement-task");
  await first.stop();

  const replacementPort = fakePort();
  const replacement = new InboxPump(replacementPort.value, recentDeliveries);
  replacement.start();
  try {
    replacementPort.deliver(structuredClone(accepted));
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(replacementPort.injections, []);
    await replacementPort.waitCalled(2);
  } finally {
    await replacement.stop();
  }
});

test("backs off recoverable waits, resets after a delivery, and stops after five failures", async () => {
  // Break caught: connection churn either hot-loops or permanently poisons the next healthy wait.
  const recovering = fakePort();
  const recoveringPump = new InboxPump(recovering.value);
  recoveringPump.start();
  recovering.fail({ kind: "recoverable" });
  await recovering.slept(250);
  recovering.releaseSleep(250);
  recovering.deliver(delivery("healthy-task"));
  await recovering.injected("healthy-task", "task");
  recoveringPump.complete("healthy-task");
  await recovering.waitCalled(3);
  recovering.fail({ kind: "recoverable" });
  await recovering.slept(250);
  await recoveringPump.stop();

  const exhausted = fakePort();
  const exhaustedPump = new InboxPump(exhausted.value);
  exhaustedPump.start();
  for (const milliseconds of [250, 500, 1_000, 2_000]) {
    exhausted.fail({ kind: "recoverable" });
    await exhausted.slept(milliseconds);
    exhausted.releaseSleep(milliseconds);
  }
  exhausted.fail({ kind: "recoverable" });
  await exhausted.unavailable();
  assert.deepEqual(exhausted.sleeps, [250, 500, 1_000, 2_000]);
  assert.equal(exhaustedPump.state, "stopped");
  await exhaustedPump.settled();
});

test("does not reset recoverable failures for a malformed delivery", async () => {
  // Break caught: an invalid native envelope hides an outage by resetting the retry threshold.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  for (const milliseconds of [250, 500, 1_000, 2_000]) {
    port.fail({ kind: "recoverable" });
    await port.slept(milliseconds);
    port.releaseSleep(milliseconds);
  }
  port.deliver({ ...delivery("malformed-between-errors"), unexpected: true });
  await port.waitCalled(6);
  port.fail({ kind: "recoverable" });
  await port.unavailable();
  assert.deepEqual(port.sleeps, [250, 500, 1_000, 2_000]);
  assert.equal(port.notifications, 1);
  await pump.settled();
});

test("stops terminal waits silently", async () => {
  // Break caught: stale-session termination is shown as a broker availability outage.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.fail({ kind: "terminal" });
  await pump.settled();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(pump.state, "stopped");
  assert.equal(port.notifications, 0);
});

test("routes one explicit waiter without injection and rejects a second waiter", async () => {
  // Break caught: compatibility waiting releases its leased task before the exact task completes.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  await port.waitCalled(1);
  const explicit = pump.waitExplicit(30_000);
  await assert.rejects(pump.waitExplicit(30_000), /already active/i);
  port.deliver(delivery("explicit-task"));

  assert.equal((await explicit).task_id, "explicit-task");
  assert.deepEqual(port.injections, []);
  assert.equal(port.waitCalls, 1);
  pump.complete("other-task");
  assert.equal(port.waitCalls, 1);
  pump.complete("explicit-task");
  await port.waitCalled(2);
  await pump.stop();
});

test("rejects explicit wait timeouts outside the 24-hour bound", async () => {
  // Break caught: a tool caller can create a waiter that exceeds the documented maximum duration.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  await assert.rejects(pump.waitExplicit(86_400_001), /timeout/i);
  assert.deepEqual(port.sleeps, []);
  await pump.stop();
});

test("cancellation removes only the explicit waiter", async () => {
  // Break caught: cancelling a local tool call aborts the shared native inbox pump.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  const controller = new AbortController();
  pump.start();
  await port.waitCalled(1);
  const explicit = pump.waitExplicit(30_000, controller.signal);
  controller.abort();
  await assert.rejects(explicit, /aborted/i);
  port.deliver(delivery("automatic-after-cancel"));
  await port.injected("automatic-after-cancel", "task");
  pump.complete("automatic-after-cancel");
  await pump.stop();
});

test("timeout removes only the explicit waiter without real-time sleeps", async () => {
  // Break caught: an explicit timeout either takes down the shared pump or needs wall-clock test delays.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  await port.waitCalled(1);
  const explicit = pump.waitExplicit(1);
  await port.slept(1);
  port.releaseSleep(1);
  await assert.rejects(explicit, /timed out/i);
  port.deliver(delivery("automatic-after-timeout"));
  await port.injected("automatic-after-timeout", "task");
  pump.complete("automatic-after-timeout");
  await pump.stop();
});

test("unexpected explicit timeout failure rejects and removes only that waiter", async () => {
  // Break caught: a failed timeout source leaves a permanent hidden local waiter.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  await port.waitCalled(1);
  const explicit = pump.waitExplicit(30_000);
  await port.slept(30_000);
  port.rejectSleep(30_000);
  await assert.rejects(explicit, /timer failed/i);
  port.deliver(delivery("automatic-after-timer-failure"));
  await port.injected("automatic-after-timer-failure", "task");
  pump.complete("automatic-after-timer-failure");
  await pump.stop();
});

test("waits behind an active automatic task before serving an explicit waiter", async () => {
  // Break caught: an explicit wait bypasses an active task and takes a second lease.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("automatic-task"));
  await port.injected("automatic-task", "task");
  const explicit = pump.waitExplicit(30_000);
  assert.equal(port.waitCalls, 1);
  pump.complete("automatic-task");
  await port.waitCalled(2);
  port.deliver(delivery("explicit-after-active"));
  assert.equal((await explicit).task_id, "explicit-after-active");
  assert.deepEqual(port.injections.map(([candidate]) => candidate.task_id), ["automatic-task"]);
  await pump.stop();
});

test("stops a pending wait without notifying availability", async () => {
  // Break caught: shutdown leaves the long wait alive or emits a misleading outage notification.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  await port.waitCalled(1);
  await pump.stop();
  assert.equal(pump.state, "stopped");
  assert.equal(port.notifications, 0);
});

test("stops an active automatic task without waiting for a reply", { timeout: 250 }, async () => {
  // Break caught: session shutdown hangs indefinitely behind a peer task that can no longer reply.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("task-stopped-while-active"));
  await port.injected("task-stopped-while-active", "task");
  await pump.stop();
  assert.equal(pump.state, "stopped");
});

test("accepts an empty delivery text at the zero-byte boundary", async () => {
  // Break caught: valid empty peer content is treated as malformed instead of being routed.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver({ ...delivery("empty-text"), payload: { text: "", metadata: {}, file_refs: [] } });
  await port.injected("empty-text", "task");
  assert.equal(port.injections[0]?.[0].text, "");
  assert.deepEqual(port.replyFailures, []);
  pump.complete("empty-text");
  await pump.stop();
});

test("settled injects one reminder before completing the active task", { timeout: 250 }, async () => {
  // Break caught: an idle Pi turn neither reminds the model nor keeps the task lease active.
  const port = fakePort();
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("reminder-task"));
  await port.injected("reminder-task", "task");
  await pump.settled();
  assert.deepEqual(port.injections.map(([candidate, kind]) => [candidate.task_id, kind]), [
    ["reminder-task", "task"],
    ["reminder-task", "reminder"],
  ]);
  assert.equal(port.waitCalls, 1);
  await pump.settled();
  assert.deepEqual(port.replyFailures, ["reminder-task"]);
  await port.waitCalled(2);
  await pump.stop();
});

test("normal completion racing fallback produces one reply failure and one release", { timeout: 250 }, async () => {
  // Break caught: a normal reply racing the deterministic fallback produces duplicate terminal work.
  const port = fakePort({ deferReplyFailure: true });
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("racing-task"));
  await port.injected("racing-task", "task");
  await pump.settled();
  const fallback = pump.settled();
  await port.replyFailureCalled("racing-task");
  pump.complete("racing-task");
  port.resolveReplyFailure();
  await fallback;
  assert.deepEqual(port.replyFailures, ["racing-task"]);
  await port.waitCalled(2);
  await pump.stop();
});

test("rejected fallback stops the pump without leasing another task", async () => {
  // Break caught: a failed deterministic reply strands the active lease and prevents fresh recovery.
  const port = fakePort({ deferReplyFailure: true });
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("fallback-failure-task"));
  await port.injected("fallback-failure-task", "task");
  await pump.settled();
  const fallback = pump.settled();
  await port.replyFailureCalled("fallback-failure-task");
  port.rejectReplyFailure();
  await assert.rejects(fallback, /fallback failed/i);
  assert.equal(pump.state, "stopped");
  assert.equal(port.notifications, 1);
  assert.equal(port.waitCalls, 1);
  await assert.doesNotReject(pump.settled());
});

test("rejected fallback stops even when availability notification throws", async () => {
  // Break caught: a throwing notification bypasses fallback cleanup and strands the active lease.
  const port = fakePort({ deferReplyFailure: true, throwOnNotify: true });
  const pump = new InboxPump(port.value);
  pump.start();
  port.deliver(delivery("fallback-notification-throw"));
  await port.injected("fallback-notification-throw", "task");
  await pump.settled();
  const fallback = pump.settled();
  await port.replyFailureCalled("fallback-notification-throw");
  port.rejectReplyFailure();
  await assert.rejects(fallback, /fallback failed/i);
  assert.equal(pump.state, "stopped");
  assert.equal(port.notifications, 1);
  assert.equal(port.waitCalls, 1);
  await assert.doesNotReject(pump.settled());
});

function delivery(taskId: string): Record<string, unknown> {
  return {
    delivery_id: deliveryId(taskId),
    task_id: taskId,
    context_id: `context-${taskId}`,
    sender: "reviewer",
    recipient: "implementer",
    payload: { text: `payload-${taskId}`, metadata: {}, file_refs: [] },
    leased_until_unix_ms: 123,
    attempt: 0,
  };
}

function deliveryId(taskId: string): string {
  const suffix = createHash("sha256").update(taskId).digest("hex").slice(0, 12);
  return `${DELIVERY_ID.slice(0, -12)}${suffix}`;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function fakePort(options: { deferReplyFailure?: boolean; throwOnNotify?: boolean } = {}) {
  const queued: Array<{ value?: unknown; error?: unknown }> = [];
  const waits: Array<ReturnType<typeof deferred<unknown>>> = [];
  const injections: Array<[InboxDelivery, InboxInjectionKind]> = [];
  const replyFailures: string[] = [];
  const pendingReplyFailures: Array<ReturnType<typeof deferred<void>>> = [];
  const sleeps: Array<{ milliseconds: number; pending: ReturnType<typeof deferred<void>> }> = [];
  const sleepHistory: number[] = [];
  let waitCalls = 0;
  let notifications = 0;
  const availability = deferred<void>();

  const next = () => {
    const pending = waits[0];
    const item = queued[0];
    if (pending === undefined || item === undefined) return;
    waits.shift();
    queued.shift();
    if ("error" in item) pending.reject(item.error);
    else pending.resolve(item.value);
  };
  const value: InboxPumpPort = {
    wait(signal) {
      waitCalls += 1;
      const pending = deferred<unknown>();
      const abort = () => pending.reject(new Error("wait aborted"));
      signal.addEventListener("abort", abort, { once: true });
      waits.push(pending);
      next();
      return pending.promise;
    },
    inject(candidate, kind) { injections.push([candidate, kind]); },
    replyFailure(taskId) {
      replyFailures.push(taskId);
      if (options.deferReplyFailure !== true) return Promise.resolve();
      const pending = deferred<void>();
      pendingReplyFailures.push(pending);
      return pending.promise;
    },
    notifyUnavailable() {
      notifications += 1;
      availability.resolve();
      if (options.throwOnNotify === true) throw new Error("notification failed");
    },
    sleep(milliseconds, signal) {
      const pending = deferred<void>();
      const abort = () => pending.reject(new Error("sleep aborted"));
      signal.addEventListener("abort", abort, { once: true });
      sleepHistory.push(milliseconds);
      sleeps.push({ milliseconds, pending });
      return pending.promise;
    },
    classifyWaitError(error) {
      if (typeof error === "object" && error !== null && "kind" in error) {
        const kind = error.kind;
        if (kind === "timeout" || kind === "recoverable" || kind === "terminal") return kind;
      }
      return "terminal";
    },
  };
  const waitFor = async (predicate: () => boolean) => {
    for (let attempts = 0; attempts < 100; attempts += 1) {
      if (predicate()) return;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.fail("condition was not reached");
  };
  return {
    value,
    deliver(candidate: unknown) { queued.push({ value: candidate }); next(); },
    fail(error: unknown) { queued.push({ error }); next(); },
    get injections() { return injections; },
    get notifications() { return notifications; },
    get replyFailures() { return replyFailures; },
    get sleeps() { return sleepHistory; },
    get waitCalls() { return waitCalls; },
    async injected(taskId: string, kind: InboxInjectionKind) {
      await waitFor(() => injections.some(([candidate, candidateKind]) => candidate.task_id === taskId && candidateKind === kind));
    },
    releaseSleep(milliseconds: number) {
      const index = sleeps.findIndex((candidate) => candidate.milliseconds === milliseconds);
      assert.notEqual(index, -1, `no pending ${milliseconds}ms sleep`);
      const [sleep] = sleeps.splice(index, 1);
      sleep!.pending.resolve();
    },
    rejectSleep(milliseconds: number) {
      const index = sleeps.findIndex((candidate) => candidate.milliseconds === milliseconds);
      assert.notEqual(index, -1, `no pending ${milliseconds}ms sleep`);
      const [sleep] = sleeps.splice(index, 1);
      sleep!.pending.reject(new Error("timer failed"));
    },
    resolveReplyFailure() {
      const pending = pendingReplyFailures.shift();
      assert.ok(pending, "no pending reply failure");
      pending.resolve();
    },
    rejectReplyFailure() {
      const pending = pendingReplyFailures.shift();
      assert.ok(pending, "no pending reply failure");
      pending.reject(new Error("fallback failed"));
    },
    async replyFailureCalled(taskId: string) { await waitFor(() => replyFailures.includes(taskId)); },
    async slept(milliseconds: number) { await waitFor(() => sleeps.some((candidate) => candidate.milliseconds === milliseconds)); },
    async unavailable() { await availability.promise; },
    async waitCalled(expected: number) { await waitFor(() => waitCalls >= expected); },
  };
}
