const MAX_AGENT_NAME_BYTES = 32;
const MAX_CONTEXT_ID_BYTES = 256;
const MAX_METADATA_BYTES = 32 * 1024;
const MAX_METADATA_DEPTH = 8;
const MAX_METADATA_ENTRIES = 256;
const MAX_TASK_ID_BYTES = 256;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_WAIT_TIMEOUT_MS = 86_400_000;
const MAX_RECENT_DELIVERY_IDS = 256;
const WAIT_RETRY_MS = [250, 500, 1_000, 2_000, 5_000] as const;

export interface InboxDelivery {
  delivery_id: string;
  task_id: string;
  conversation_id: string;
  sender: string;
  recipient: string;
  text: string;
  metadata: Record<string, unknown>;
  leased_until_unix_ms: number;
  attempt: number;
}

export type InboxInjectionKind = "task" | "reminder";
export type InboxState = "stopped" | "waiting" | "delivering-explicitly"
  | "queued-for-pi" | "active" | "reminding" | "failing";

export interface InboxPumpPort {
  wait(signal: AbortSignal): Promise<unknown>;
  inject(delivery: InboxDelivery, kind: InboxInjectionKind): void;
  replyFailure(taskId: string, signal: AbortSignal): Promise<void>;
  notifyUnavailable(): void;
  sleep(milliseconds: number, signal: AbortSignal): Promise<void>;
  classifyWaitError(error: unknown): "timeout" | "recoverable" | "terminal";
}

type DeliveryAdmission = "accepted" | "replay" | "conflict";

export class RecentInboxDeliveries {
  readonly #fingerprints = new Map<string, string>();

  admit(delivery: InboxDelivery): DeliveryAdmission {
    const fingerprint = deliveryFingerprint(delivery);
    const prior = this.#fingerprints.get(delivery.delivery_id);
    if (prior !== undefined) return prior === fingerprint ? "replay" : "conflict";

    this.#fingerprints.set(delivery.delivery_id, fingerprint);
    if (this.#fingerprints.size > MAX_RECENT_DELIVERY_IDS) {
      const oldest = this.#fingerprints.keys().next().value;
      if (oldest !== undefined) this.#fingerprints.delete(oldest);
    }
    return "accepted";
  }
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

interface ExplicitWaiter {
  settle(error: Error | undefined, delivery?: InboxDelivery): void;
}

export class InboxPump {
  readonly #port: InboxPumpPort;
  readonly #recentDeliveries: RecentInboxDeliveries;
  #state: InboxState = "stopped";
  #controller: AbortController | undefined;
  #loop: Promise<void> | undefined;
  #activeDelivery: InboxDelivery | undefined;
  #activeTaskId: string | undefined;
  #completion: Deferred<void> | undefined;
  #settlementCount = 0;
  #fallback: Promise<void> | undefined;
  #explicitWaiter: ExplicitWaiter | undefined;
  #unavailableNotified = false;

  constructor(port: InboxPumpPort, recentDeliveries = new RecentInboxDeliveries()) {
    this.#port = port;
    this.#recentDeliveries = recentDeliveries;
  }

  get state(): InboxState {
    return this.#state;
  }

  start(): void {
    if (this.#controller !== undefined) return;
    const controller = new AbortController();
    this.#controller = controller;
    this.#unavailableNotified = false;
    this.#loop = this.#run(controller).finally(() => {
      if (this.#controller !== controller) return;
      this.#controller = undefined;
      this.#clearActive();
      this.#state = "stopped";
    });
  }

  waitExplicit(timeoutMs: number, signal?: AbortSignal): Promise<InboxDelivery> {
    if (this.#controller === undefined) return Promise.reject(new Error("inbox pump is not running"));
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_WAIT_TIMEOUT_MS) {
      return Promise.reject(new Error("explicit inbox wait timeout must be between 1 and 86400000 milliseconds"));
    }
    if (this.#explicitWaiter !== undefined) {
      return Promise.reject(new Error("an explicit inbox wait is already active"));
    }
    if (signal?.aborted === true) return Promise.reject(new Error("explicit inbox wait aborted"));

    return new Promise<InboxDelivery>((resolve, reject) => {
      let done = false;
      const timeoutController = new AbortController();
      const onAbort = () => settle(new Error("explicit inbox wait aborted"));
      const settle = (error: Error | undefined, delivery?: InboxDelivery) => {
        if (done) return;
        done = true;
        timeoutController.abort();
        signal?.removeEventListener("abort", onAbort);
        if (this.#explicitWaiter?.settle === waiter.settle) this.#explicitWaiter = undefined;
        if (error !== undefined) reject(error);
        else resolve(delivery!);
      };
      const waiter: ExplicitWaiter = { settle };
      this.#explicitWaiter = waiter;
      signal?.addEventListener("abort", onAbort, { once: true });
      void this.#port.sleep(timeoutMs, timeoutController.signal).then(
        () => settle(new Error("explicit inbox wait timed out")),
        () => {
          if (!done) settle(new Error("explicit inbox wait timer failed"));
        },
      );
    });
  }

  complete(taskId: string): void {
    if (taskId !== this.#activeTaskId || this.#completion === undefined) return;
    const completion = this.#completion;
    this.#clearActive();
    completion.resolve();
  }

  async settled(): Promise<void> {
    const delivery = this.#activeDelivery;
    const controller = this.#controller;
    if (delivery === undefined || controller === undefined || controller.signal.aborted) return;
    if (this.#settlementCount === 0) {
      this.#settlementCount = 1;
      this.#state = "reminding";
      this.#port.inject(delivery, "reminder");
      return;
    }
    if (this.#fallback !== undefined) {
      await this.#fallback;
      return;
    }
    this.#state = "failing";
    this.#fallback = this.#port.replyFailure(delivery.task_id, controller.signal)
      .then(() => {
        this.complete(delivery.task_id);
      })
      .catch(async (error: unknown) => {
        if (this.#activeDelivery !== delivery || controller.signal.aborted) return;
        try {
          await this.stop();
        } catch {
          // Preserve the fallback failure as the initiating error after best-effort cleanup.
        }
        try {
          this.#notifyUnavailable();
        } catch {
          // A notification callback must not replace the rejected fallback result.
        }
        throw error;
      });
    await this.#fallback;
  }

  async stop(): Promise<void> {
    this.#explicitWaiter?.settle(new Error("inbox pump stopped"));
    const controller = this.#controller;
    if (controller === undefined) return;
    const completion = this.#completion;
    this.#clearActive();
    completion?.resolve();
    controller.abort();
    await this.#loop;
  }

  async #run(controller: AbortController): Promise<void> {
    let consecutiveFailures = 0;

    while (!controller.signal.aborted) {
      this.#state = "waiting";
      let raw: unknown;
      try {
        raw = await this.#port.wait(controller.signal);
      } catch (error) {
        if (controller.signal.aborted) return;
        const classification = this.#port.classifyWaitError(error);
        if (classification === "timeout") continue;
        if (classification === "terminal") {
          return;
        }
        consecutiveFailures += 1;
        if (consecutiveFailures === WAIT_RETRY_MS.length) {
          this.#notifyUnavailable();
          return;
        }
        try {
          await this.#port.sleep(WAIT_RETRY_MS[consecutiveFailures - 1]!, controller.signal);
        } catch {
          if (controller.signal.aborted) return;
          this.#notifyUnavailable();
          return;
        }
        continue;
      }

      const delivery = parseDelivery(raw);
      if (delivery === undefined) {
        const taskId = taskIdFromMalformedDelivery(raw);
        if (taskId !== undefined) {
          this.#state = "failing";
          try {
            await this.#port.replyFailure(taskId, controller.signal);
          } catch {
            if (controller.signal.aborted) return;
            this.#notifyUnavailable();
            return;
          }
        }
        continue;
      }

      consecutiveFailures = 0;
      if (this.#recentDeliveries.admit(delivery) !== "accepted") continue;

      const explicitWaiter = this.#explicitWaiter;
      if (explicitWaiter !== undefined) {
        this.#state = "delivering-explicitly";
        const completion = this.#activate(delivery);
        explicitWaiter.settle(undefined, delivery);
        this.#state = "active";
        await completion.promise;
        continue;
      }

      this.#state = "queued-for-pi";
      const completion = this.#activate(delivery);
      this.#port.inject(delivery, "task");
      this.#state = "active";
      await completion.promise;
    }
  }

  #activate(delivery: InboxDelivery): Deferred<void> {
    const completion = createDeferred<void>();
    this.#activeDelivery = delivery;
    this.#activeTaskId = delivery.task_id;
    this.#completion = completion;
    this.#settlementCount = 0;
    this.#fallback = undefined;
    return completion;
  }

  #clearActive(): void {
    this.#activeDelivery = undefined;
    this.#activeTaskId = undefined;
    this.#completion = undefined;
    this.#settlementCount = 0;
    this.#fallback = undefined;
  }

  #notifyUnavailable(): void {
    if (this.#unavailableNotified) return;
    this.#unavailableNotified = true;
    this.#port.notifyUnavailable();
  }
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function deliveryFingerprint(delivery: InboxDelivery): string {
  return JSON.stringify(delivery);
}

function parseDelivery(value: unknown): InboxDelivery | undefined {
  if (!isRecord(value)
    || !hasExactKeys(value, [
      "delivery_id", "task_id", "context_id", "sender", "recipient", "payload", "leased_until_unix_ms", "attempt",
    ])
    || !isUuidV7(value.delivery_id)
    || !isTaskId(value.task_id)
    || !isBoundedString(value.context_id, MAX_CONTEXT_ID_BYTES)
    || !isAgentName(value.sender)
    || !isAgentName(value.recipient)
    || !isRecord(value.payload)
    || !hasExactKeys(value.payload, ["text", "metadata", "file_refs"])
    || !isBoundedText(value.payload.text)
    || !isMetadata(value.payload.metadata)
    || !Array.isArray(value.payload.file_refs)
    || value.payload.file_refs.length !== 0
    || typeof value.leased_until_unix_ms !== "number"
    || !Number.isSafeInteger(value.leased_until_unix_ms)
    || typeof value.attempt !== "number"
    || !Number.isSafeInteger(value.attempt)
    || value.attempt < 0) {
    return undefined;
  }
  return {
    delivery_id: value.delivery_id,
    task_id: value.task_id,
    conversation_id: value.context_id,
    sender: value.sender,
    recipient: value.recipient,
    text: value.payload.text,
    metadata: value.payload.metadata,
    leased_until_unix_ms: value.leased_until_unix_ms,
    attempt: value.attempt,
  };
}

function taskIdFromMalformedDelivery(value: unknown): string | undefined {
  return isRecord(value) && isTaskId(value.task_id) ? value.task_id : undefined;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isAgentName(value: unknown): value is string {
  return isBoundedString(value, MAX_AGENT_NAME_BYTES) && /^[a-z][a-z0-9_-]*$/u.test(value);
}

function isBoundedString(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function isBoundedText(value: unknown): value is string {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= MAX_TEXT_BYTES;
}

function isMetadata(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value) || Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_METADATA_BYTES) return false;
  let entries = 0;
  const valid = (candidate: unknown, depth: number): boolean => {
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return true;
    if (typeof candidate === "number") return Number.isFinite(candidate);
    if (Array.isArray(candidate)) {
      if (depth + 1 > MAX_METADATA_DEPTH) return false;
      entries += candidate.length;
      return entries <= MAX_METADATA_ENTRIES && candidate.every((item) => valid(item, depth + 1));
    }
    if (!isRecord(candidate)) return false;
    if (depth + 1 > MAX_METADATA_DEPTH) return false;
    entries += Object.keys(candidate).length;
    return entries <= MAX_METADATA_ENTRIES && Object.values(candidate).every((item) => valid(item, depth + 1));
  };
  return valid(value, 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTaskId(value: unknown): value is string {
  return isBoundedString(value, MAX_TASK_ID_BYTES) && /^[A-Za-z0-9_-]+$/u.test(value);
}

function isUuidV7(value: unknown): value is string {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}
