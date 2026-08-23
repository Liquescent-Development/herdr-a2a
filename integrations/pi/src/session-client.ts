import { createHash } from "node:crypto";
import { execFile as nodeExecFile, spawn as nodeSpawn } from "node:child_process";
import { constants } from "node:fs";
import type { BigIntStats } from "node:fs";
import { access, lstat, open, realpath, stat, type FileHandle } from "node:fs/promises";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import type { Readable, Writable } from "node:stream";
import { TextDecoder } from "node:util";
import { promisify } from "node:util";

export const MAX_NDJSON_LINE_BYTES = 512 * 1024;
export const MAX_AGENT_NAME_BYTES = 32;
export const MAX_TASK_ID_BYTES = 256;
const MAX_DESCRIPTOR_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_IDENTITY_BYTES = 1024;
const MAX_SESSION_ERROR_CANDIDATES = 1_024;
const MAX_WORKSPACE_ID_BYTES = 256;
const MAX_COMMAND_OUTPUT_BYTES = 64 * 1024;
const MANAGED_COMMAND_TIMEOUT_MS = 10_000;
const DEFAULT_TERM_GRACE_MS = 500;
const DEFAULT_KILL_GRACE_MS = 500;
const DEFAULT_READINESS_TIMEOUT_MS = 5_000;
const MAX_FUTURE_DESCRIPTOR_MS = 5 * 60 * 1_000;
const MAX_PLATFORM_PID = 2_147_483_647;
const execFile = promisify(nodeExecFile);

export function isBoundedUtf8String(
  value: unknown,
  maximumBytes: number,
): value is string {
  return typeof value === "string"
    && value.length > 0
    && Buffer.byteLength(value, "utf8") <= maximumBytes;
}

export interface SessionProcess {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: "error", listener: (error: Error) => void): this;
  kill(signal?: NodeJS.Signals | number): boolean;
}

export interface SessionClientOptions {
  termGraceMs?: number;
  killGraceMs?: number;
}

interface PendingRequest {
  resolve(value: unknown): void;
  reject(error: Error): void;
}

export interface SessionRequestErrorDetails {
  candidates: string[];
}

export class SessionRequestError extends Error {
  readonly code: string;
  readonly details: SessionRequestErrorDetails | undefined;

  constructor(code: string, message: string, details?: SessionRequestErrorDetails) {
    const candidates = details === undefined ? "" : ` (candidates: ${details.candidates.join(", ")})`;
    super(`${code}: ${message}${candidates}`);
    this.name = "SessionRequestError";
    this.code = code;
    this.details = details;
  }
}

export class SessionRequestAbortedError extends Error {
  readonly source = "request-signal" as const;

  constructor() {
    super("client session request aborted");
    this.name = "SessionRequestAbortedError";
  }
}

export class SessionClient {
  readonly #process: SessionProcess;
  readonly #pending = new Map<string, PendingRequest>();
  #nextId = 1;
  #stdout = Buffer.alloc(0);
  #stderr = Buffer.alloc(0);
  #terminalError: Error | undefined;
  #processExited = false;
  #processClosed = false;
  readonly #processClose: Promise<void>;
  #resolveProcessClose!: () => void;
  #retirementPromise: Promise<void> | undefined;
  readonly #termGraceMs: number;
  readonly #killGraceMs: number;

  constructor(process: SessionProcess, options: SessionClientOptions = {}) {
    this.#process = process;
    this.#termGraceMs = boundedGrace(options.termGraceMs, DEFAULT_TERM_GRACE_MS);
    this.#killGraceMs = boundedGrace(options.killGraceMs, DEFAULT_KILL_GRACE_MS);
    this.#processExited = process.exitCode !== null || process.signalCode !== null;
    this.#processClose = new Promise((resolve) => { this.#resolveProcessClose = resolve; });
    process.stdout.on("data", (chunk: Buffer | string) => this.#acceptStdout(chunk));
    process.stderr.on("data", (chunk: Buffer | string) => this.#acceptStderr(chunk));
    process.stdin.on("error", (error) => this.#fail(new Error(`client session stdin error: ${error.message}`)));
    process.stdout.on("error", (error) => this.#fail(new Error(`client session stdout error: ${error.message}`)));
    process.stderr.on("error", (error) => this.#fail(new Error(`client session stderr error: ${error.message}`)));
    process.stdout.on("end", () => this.#fail(new Error("client session stdout ended unexpectedly")));
    process.stdout.on("close", () => this.#fail(new Error("client session stdout ended unexpectedly")));
    process.on("error", (error) => this.#fail(new Error(`client session process error: ${error.message}`)));
    process.on("exit", (code, signal) => {
      this.#processExited = true;
      if (this.#terminalError !== undefined) return;
      const status = code === null ? `from signal ${signal ?? "unknown"}` : `with code ${code}`;
      const context = this.#stderr.length === 0 ? "" : `: ${this.#stderr.toString("utf8")}`;
      this.#fail(new Error(`client session exited ${status}${context}`), false);
    });
    process.on("close", (code, signal) => {
      this.#processExited = true;
      this.#processClosed = true;
      this.#resolveProcessClose();
      if (this.#terminalError === undefined) {
        const status = code === null ? `from signal ${signal ?? "unknown"}` : `with code ${code}`;
        this.#fail(new Error(`client session closed ${status}`), false);
      }
    });
  }

  get closed(): boolean {
    return this.#terminalError !== undefined;
  }

  call(
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (this.#terminalError !== undefined) return Promise.reject(this.#terminalError);
    if (signal?.aborted === true) return Promise.reject(new SessionRequestAbortedError());
    const id = String(this.#nextId++);
    const line = `${JSON.stringify({ id, method, params })}\n`;
    if (Buffer.byteLength(line) - 1 > MAX_NDJSON_LINE_BYTES) {
      return Promise.reject(new Error("client session request exceeds the bounded NDJSON line size"));
    }
    return new Promise((resolve, reject) => {
      const removeAbortListener = (): void => signal?.removeEventListener("abort", abort);
      const abort = (): void => this.#fail(new SessionRequestAbortedError());
      this.#pending.set(id, {
        resolve: (value) => {
          removeAbortListener();
          resolve(value);
        },
        reject: (error) => {
          removeAbortListener();
          reject(error);
        },
      });
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) {
        abort();
        return;
      }
      this.#process.stdin.write(line, (error) => {
        if (error) this.#fail(new Error(`client session stdin error: ${error.message}`));
      });
    });
  }

  close(): Promise<void> {
    if (this.#terminalError === undefined) {
      this.#terminalError = new Error("client session closed");
      this.#rejectPending(this.#terminalError);
    }
    return this.#retire();
  }

  #acceptStdout(chunk: Buffer | string): void {
    if (this.#terminalError !== undefined) return;
    this.#stdout = Buffer.concat([this.#stdout, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    while (true) {
      const newline = this.#stdout.indexOf(0x0a);
      if (newline === -1) {
        if (this.#stdout.length > MAX_NDJSON_LINE_BYTES) {
          this.#protocolError("response line exceeds the bounded envelope size");
        }
        return;
      }
      if (newline > MAX_NDJSON_LINE_BYTES) {
        this.#protocolError("response line exceeds the bounded envelope size");
        return;
      }
      let line = this.#stdout.subarray(0, newline);
      this.#stdout = this.#stdout.subarray(newline + 1);
      if (line.at(-1) === 0x0d) line = line.subarray(0, -1);
      this.#acceptLine(line);
      if (this.#terminalError !== undefined) return;
    }
  }

  #acceptLine(line: Buffer): void {
    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(line);
    } catch {
      this.#protocolError("response is not valid UTF-8");
      return;
    }
    let value: unknown;
    try {
      value = JSON.parse(decoded);
    } catch (error) {
      this.#protocolError(`invalid JSON response: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    if (!isRecord(value) || typeof value.id !== "string") {
      this.#protocolError("response must be an object with a string ID");
      return;
    }
    const keys = Object.keys(value);
    if (keys.some((key) => key !== "id" && key !== "result" && key !== "error")) {
      this.#protocolError("response contains unknown fields");
      return;
    }
    const hasResult = Object.hasOwn(value, "result");
    const hasError = Object.hasOwn(value, "error");
    if (hasResult === hasError) {
      this.#protocolError("response must contain exactly one of result or error");
      return;
    }
    const pending = this.#pending.get(value.id);
    if (pending === undefined) {
      this.#protocolError("response ID does not match pending work");
      return;
    }
    if (hasError) {
      const responseError = value.error;
      if (!isRecord(responseError)
        || typeof responseError.code !== "string"
        || typeof responseError.message !== "string"
        || !hasExactKeys(
          responseError,
          Object.hasOwn(responseError, "details")
            ? ["code", "details", "message"]
            : ["code", "message"],
        )) {
        this.#protocolError("response error has an invalid shape");
        return;
      }
      let details: SessionRequestErrorDetails | undefined;
      if (Object.hasOwn(responseError, "details")) {
        const candidateDetails = responseError.details;
        if (!isRecord(candidateDetails)
          || !hasExactKeys(candidateDetails, ["candidates"])
          || !Array.isArray(candidateDetails.candidates)
          || candidateDetails.candidates.length === 0
          || candidateDetails.candidates.length > MAX_SESSION_ERROR_CANDIDATES
          || candidateDetails.candidates.some((candidate) => (
            typeof candidate !== "string"
            || Buffer.byteLength(candidate, "utf8") > MAX_AGENT_NAME_BYTES
            || !/^[a-z][a-z0-9_-]{0,31}$/u.test(candidate)
          ))
          || candidateDetails.candidates.some((candidate, index, candidates) => (
            index > 0 && candidates[index - 1] >= candidate
          ))) {
          this.#protocolError("response error details have an invalid shape");
          return;
        }
        details = { candidates: [...candidateDetails.candidates] };
      }
      this.#pending.delete(value.id);
      pending.reject(new SessionRequestError(responseError.code, responseError.message, details));
    } else {
      this.#pending.delete(value.id);
      pending.resolve(value.result);
    }
  }

  #acceptStderr(chunk: Buffer | string): void {
    const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.#stderr = Buffer.concat([this.#stderr, incoming]);
    if (this.#stderr.length > MAX_STDERR_BYTES) {
      this.#stderr = this.#stderr.subarray(this.#stderr.length - MAX_STDERR_BYTES);
    }
  }

  #protocolError(message: string): void {
    this.#fail(new Error(`client session protocol error: ${message}`));
  }

  #fail(error: Error, kill = true): void {
    if (this.#terminalError !== undefined) return;
    this.#terminalError = error;
    this.#rejectPending(error);
    if (kill) void this.#retire().catch(() => undefined);
  }

  #rejectPending(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }

  #retire(): Promise<void> {
    if (this.#retirementPromise !== undefined) return this.#retirementPromise;
    this.#retirementPromise = this.#retireProcess();
    return this.#retirementPromise;
  }

  async #retireProcess(): Promise<void> {
    try {
      this.#process.stdin.end();
    } catch {
      // A closed/broken pipe is already terminal; process signaling still owns retirement.
    }
    if (this.#processClosed) return;
    if (this.#hasExited()) {
      await this.#waitForClose(this.#killGraceMs);
      return;
    }

    const termSent = this.#sendSignal("SIGTERM");
    if (termSent && await this.#waitForClose(this.#termGraceMs)) return;
    if (this.#processClosed) return;

    if (!this.#hasExited()) {
      this.#sendSignal("SIGKILL");
    }
    if (await this.#waitForClose(this.#killGraceMs)) return;
    if (this.#hasExited()) return;
    throw new Error("client session child could not be terminated within the bounded grace period");
  }

  #hasExited(): boolean {
    return this.#processExited
      || this.#process.exitCode !== null
      || this.#process.signalCode !== null;
  }

  #sendSignal(signal: NodeJS.Signals): boolean {
    if (this.#hasExited()) return true;
    try {
      return this.#process.kill(signal);
    } catch {
      return false;
    }
  }

  async #waitForClose(milliseconds: number): Promise<boolean> {
    if (this.#processClosed) return true;
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), milliseconds);
      void this.#processClose.then(() => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }
}

function boundedGrace(value: number | undefined, fallback: number): number {
  return value === undefined || !Number.isFinite(value) || value < 0 ? fallback : value;
}

export interface RuntimeDescriptor {
  session_key: string;
  workspace_id: string;
  base_url: string;
  bearer_token: string;
  broker_instance_id: string;
  executable_path: string;
  broker_pid: number;
  created_unix_ms: number;
}

type Spawn = (
  file: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv; stdio: ["pipe", "pipe", "pipe"] },
) => SessionProcess;

export interface StartSessionClientOptions {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  uid?: number;
  spawn?: Spawn;
  readinessTimeoutMs?: number;
  checkExecutableAccess?: (path: string) => Promise<void>;
  signal?: AbortSignal;
}

interface ManagedCommandResult {
  stdout: string;
  stderr: string;
}

type ManagedCommandRunner = (
  file: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv },
) => Promise<ManagedCommandResult>;

type ManagedCommandLauncher = (
  file: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv },
) => Promise<void>;

export interface ManagedPluginOptions {
  env?: NodeJS.ProcessEnv;
  runCommand?: ManagedCommandRunner;
  launchCommand?: ManagedCommandLauncher;
  descriptorReadyTimeoutMs?: number;
  descriptorRetryDelayMs?: number;
  signal?: AbortSignal;
}

const DEFAULT_DESCRIPTOR_READY_TIMEOUT_MS = 10_000;
const DEFAULT_DESCRIPTOR_RETRY_DELAY_MS = 20;
const MAX_DESCRIPTOR_READY_TIMEOUT_MS = 30_000;

export async function isManagedPluginActive(
  options: ManagedPluginOptions = {},
): Promise<boolean> {
  const env = options.env ?? process.env;
  if (!hasSafeManagedContext(env)) return false;
  try {
    const herdr = await resolveManagedHerdrBinary(env);
    const result = await (options.runCommand ?? runManagedCommand)(
      herdr,
      ["plugin", "list", "--plugin", "herdr.a2a", "--json"],
      { env },
    );
    return parseManagedPluginList(result.stdout);
  } catch {
    return false;
  }
}

export async function ensureWorkspaceBroker(
  options: ManagedPluginOptions = {},
): Promise<void> {
  const signal = options.signal;
  throwIfAborted(signal, "broker ensure aborted");
  const env = options.env ?? process.env;
  if (!hasSafeManagedContext(env)) {
    throw new Error("managed Herdr workspace and pane context is required");
  }
  const runCommand = options.runCommand ?? runManagedCommand;
  const herdr = await awaitWithAbort(
    resolveManagedHerdrBinary(env),
    signal,
    "broker ensure aborted",
  );
  const dispatchEnv = await awaitWithAbort(
    managedNativeEnvironment(env, herdr),
    signal,
    "broker ensure aborted",
  );
  const registration = await awaitWithAbort(
    runCommand(
      herdr,
      ["plugin", "list", "--plugin", "herdr.a2a", "--json"],
      { env: dispatchEnv },
    ),
    signal,
    "broker ensure aborted",
  );
  const pluginRoot = parseManagedPluginRoot(registration.stdout);
  if (pluginRoot === undefined) {
    throw new Error("registered managed Herdr A2A plugin is unavailable");
  }
  await awaitWithAbort(
    (options.launchCommand ?? launchManagedCommand)(
      join(pluginRoot, "libexec", "herdr-a2a-dispatch"),
      ["coordinator", "dispatch-exec", "--", "coordinator", "serve"],
      { env: dispatchEnv },
    ),
    signal,
    "broker ensure aborted",
  );
  const timeoutMs = options.descriptorReadyTimeoutMs ?? DEFAULT_DESCRIPTOR_READY_TIMEOUT_MS;
  const retryDelayMs = options.descriptorRetryDelayMs ?? DEFAULT_DESCRIPTOR_RETRY_DELAY_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_DESCRIPTOR_READY_TIMEOUT_MS) {
    throw new Error("descriptor readiness timeout must be a positive bounded integer");
  }
  if (!Number.isSafeInteger(retryDelayMs) || retryDelayMs <= 0 || retryDelayMs > timeoutMs) {
    throw new Error("descriptor retry delay must be a positive integer within the readiness timeout");
  }
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      await awaitWithAbort(
        loadRuntimeDescriptor({ env }),
        signal,
        "broker ensure aborted",
      );
      return;
    } catch {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error(
          "authenticated runtime descriptor was not published before the readiness deadline",
        );
      }
      await abortableDelay(
        Math.min(retryDelayMs, remaining),
        signal,
        "broker ensure aborted",
      );
    }
  }
}

export type LoadRuntimeDescriptorOptions = Pick<
  StartSessionClientOptions,
  "env" | "platform" | "uid" | "checkExecutableAccess"
>;

export async function loadRuntimeDescriptor(
  options: LoadRuntimeDescriptorOptions = {},
): Promise<RuntimeDescriptor> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const uid = options.uid ?? process.getuid?.();
  const socketPath = env.HERDR_SOCKET_PATH;
  if (socketPath === undefined || !isSafeAbsolutePath(socketPath)) {
    throw new Error("HERDR_SOCKET_PATH must be a safe absolute path");
  }
  const workspaceId = env.HERDR_WORKSPACE_ID;
  if (!isValidWorkspaceId(workspaceId)) {
    throw new Error("HERDR_WORKSPACE_ID must be non-empty, bounded, and contain no controls");
  }
  const sessionKey = createHash("sha256").update(socketPath).digest("hex");
  const scopeKey = createHash("sha256")
    .update(sessionKey)
    .update("\0")
    .update(workspaceId)
    .digest("hex");
  const runtimeRoot = runtimeRootFor(platform, env, uid);
  if (uid === undefined) throw new Error("the current user ID is required");
  const descriptorPath = join(runtimeRoot, `${scopeKey}.json`);
  const rootHandle = await openProtectedRuntimeRoot(runtimeRoot, uid);
  let descriptor: RuntimeDescriptor;
  try {
    descriptor = await readProtectedDescriptor(descriptorPath, runtimeRoot, rootHandle, uid);
  } finally {
    await rootHandle.close();
  }
  validateDescriptor(descriptor, sessionKey, workspaceId);
  const canonicalExecutable = await realpath(descriptor.executable_path);
  if (canonicalExecutable !== descriptor.executable_path) {
    throw new Error("runtime descriptor executable path is not canonical");
  }
  const executable = await stat(canonicalExecutable);
  if (!executable.isFile()) {
    throw new Error("runtime descriptor executable is not executable");
  }
  if (!realAndEffectiveCredentialsMatch()) {
    throw new Error("runtime descriptor executable access cannot be verified under differing credentials");
  }
  try {
    await (options.checkExecutableAccess ?? checkExecutableAccess)(canonicalExecutable);
  } catch {
    throw new Error("runtime descriptor executable is not executable by this process");
  }
  if ((executable.mode & 0o111) === 0) {
    throw new Error("runtime descriptor executable is not executable by this process");
  }
  return descriptor;
}

export async function startSessionClient(
  harnessSessionId: string,
  options: StartSessionClientOptions = {},
): Promise<SessionClient> {
  if (harnessSessionId.length === 0 || Buffer.byteLength(harnessSessionId) > MAX_IDENTITY_BYTES) {
    throw new Error("Pi session ID must be non-empty and bounded");
  }
  throwIfAborted(options.signal, "client session startup aborted");
  const env = options.env ?? process.env;
  const descriptor = await awaitWithAbort(
    loadRuntimeDescriptor(options),
    options.signal,
    "client session startup aborted",
  );
  const canonicalExecutable = descriptor.executable_path;
  const childEnv = env.HERDR_ENV === "1"
    ? await managedNativeEnvironment(env)
    : env;
  const spawn = options.spawn ?? ((file, args, spawnOptions) => nodeSpawn(file, args, spawnOptions));
  const child = spawn(
    canonicalExecutable,
    ["client-session", "--harness-session-id", harnessSessionId],
    { env: childEnv, stdio: ["pipe", "pipe", "pipe"] },
  );
  const client = new SessionClient(child);
  const readinessController = new AbortController();
  let readinessTimedOut = false;
  let startupAborted = false;
  const abortStartup = (): void => {
    startupAborted = true;
    readinessController.abort();
  };
  options.signal?.addEventListener("abort", abortStartup, { once: true });
  if (options.signal?.aborted === true) abortStartup();
  const readinessTimer = setTimeout(() => {
    readinessTimedOut = true;
    readinessController.abort();
  }, boundedGrace(options.readinessTimeoutMs, DEFAULT_READINESS_TIMEOUT_MS));
  try {
    const readiness = await client.call("list_agents", {}, readinessController.signal);
    if (!isRecord(readiness) || !Array.isArray(readiness.agents)) {
      throw new Error("client session readiness response has an invalid shape");
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (client.closed) {
      throw new Error("client session exited during readiness");
    }
    return client;
  } catch (error) {
    const startupError = startupAborted
      ? new Error("client session startup aborted", { cause: error })
      : readinessTimedOut
      ? new Error("client session readiness timed out", { cause: error })
      : error;
    try {
      await client.close();
    } catch (retirementError) {
      throw new AggregateError(
        [startupError, retirementError],
        "client session startup failed and its child could not be retired",
      );
    }
    throw startupError;
  } finally {
    clearTimeout(readinessTimer);
    options.signal?.removeEventListener("abort", abortStartup);
  }
}

async function runManagedCommand(
  file: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv },
): Promise<ManagedCommandResult> {
  const result = await execFile(file, args, {
    env: options.env,
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    timeout: MANAGED_COMMAND_TIMEOUT_MS,
  });
  return { stdout: String(result.stdout), stderr: String(result.stderr) };
}

async function launchManagedCommand(
  file: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv },
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = nodeSpawn(file, args, {
      env: options.env,
      detached: true,
      stdio: "ignore",
    });
    const onError = (error: Error): void => {
      child.removeListener("spawn", onSpawn);
      reject(error);
    };
    const onSpawn = (): void => {
      child.removeListener("error", onError);
      child.unref();
      resolve();
    };
    child.once("error", onError);
    child.once("spawn", onSpawn);
  });
}

function hasSafeManagedContext(env: NodeJS.ProcessEnv): boolean {
  return env.HERDR_ENV === "1"
    && isSafeIdentity(env.HERDR_WORKSPACE_ID, MAX_WORKSPACE_ID_BYTES)
    && isSafeIdentity(env.HERDR_PANE_ID, MAX_IDENTITY_BYTES);
}

function isSafeIdentity(value: unknown, maximumBytes: number): value is string {
  return isBoundedUtf8String(value, maximumBytes)
    && !/[\p{Cc}\u2028\u2029]/u.test(value);
}

async function resolveManagedHerdrBinary(env: NodeJS.ProcessEnv): Promise<string> {
  const configured = env.HERDR_BIN_PATH;
  if (configured !== undefined) {
    if (configured.length > MAX_IDENTITY_BYTES || !isSafeAbsolutePath(configured)) {
      throw new Error("HERDR_BIN_PATH must be a safe bounded absolute path");
    }
    return configured;
  }
  const search = env.PATH;
  if (!isSafeIdentity(search, MAX_COMMAND_OUTPUT_BYTES)) {
    throw new Error("PATH must be non-empty, bounded, and control-free");
  }
  for (const component of search.split(delimiter)) {
    if (!isSafeAbsolutePath(component)) {
      throw new Error("PATH entries must be safe absolute paths");
    }
    const candidate = join(component, "herdr");
    try {
      const resolved = await realpath(candidate);
      if (resolved.length > MAX_IDENTITY_BYTES || !isSafeAbsolutePath(resolved)) continue;
      const metadata = await stat(resolved);
      if (!metadata.isFile()) continue;
      await access(resolved, constants.X_OK);
      return resolved;
    } catch {
      // Continue through the caller's bounded absolute PATH without invoking a shell.
    }
  }
  throw new Error("the Herdr executable could not be resolved from PATH");
}

async function managedNativeEnvironment(
  env: NodeJS.ProcessEnv,
  resolvedHerdr?: string,
): Promise<NodeJS.ProcessEnv> {
  if (!hasSafeManagedContext(env)) {
    throw new Error("managed Herdr workspace and pane context is required");
  }
  return {
    ...env,
    HERDR_BIN_PATH: resolvedHerdr ?? await resolveManagedHerdrBinary(env),
    HERDR_PLUGIN_STATE_DIR: managedPluginStateDir(env),
  };
}

function managedPluginStateDir(env: NodeJS.ProcessEnv): string {
  const configured = env.HERDR_PLUGIN_STATE_DIR;
  if (configured !== undefined) {
    if (configured.length > MAX_COMMAND_OUTPUT_BYTES || !isSafeAbsolutePath(configured)) {
      throw new Error("HERDR_PLUGIN_STATE_DIR must be a safe bounded absolute path");
    }
    return configured;
  }
  const base = env.XDG_STATE_HOME === undefined
    ? join(requiredSafeHome(env), ".local", "state")
    : env.XDG_STATE_HOME;
  if (base.length > MAX_COMMAND_OUTPUT_BYTES || !isSafeAbsolutePath(base)) {
    throw new Error("the managed plugin state base must be a safe bounded absolute path");
  }
  return join(base, "herdr", "plugins", "herdr.a2a");
}

function requiredSafeHome(env: NodeJS.ProcessEnv): string {
  const home = env.HOME;
  if (home === undefined || home.length > MAX_IDENTITY_BYTES || !isSafeAbsolutePath(home)) {
    throw new Error("HOME must be a safe bounded absolute path");
  }
  return home;
}

function parseManagedPluginList(encoded: string): boolean {
  const plugin = parseManagedPlugin(encoded);
  return plugin !== undefined
    && plugin.plugin_id === "herdr.a2a"
    && plugin.enabled === true;
}

function parseManagedPluginRoot(encoded: string): string | undefined {
  const plugin = parseManagedPlugin(encoded);
  if (plugin === undefined
    || plugin.plugin_id !== "herdr.a2a"
    || plugin.enabled !== true
    || typeof plugin.plugin_root !== "string"
    || !isSafeAbsolutePath(plugin.plugin_root)) {
    return undefined;
  }
  return plugin.plugin_root;
}

function parseManagedPlugin(encoded: string): Record<string, unknown> | undefined {
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    return undefined;
  }
  if (!isRecord(value) || !hasExactKeys(value, ["id", "result"]) || typeof value.id !== "string") {
    return undefined;
  }
  const result = value.result;
  if (!isRecord(result)
    || !hasExactKeys(result, ["plugins", "type"])
    || result.type !== "plugin_list"
    || !Array.isArray(result.plugins)
    || result.plugins.length !== 1) {
    return undefined;
  }
  const plugin = result.plugins[0];
  return isRecord(plugin) ? plugin : undefined;
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === [...expected].sort()[index]);
}

function runtimeRootFor(platform: NodeJS.Platform, env: NodeJS.ProcessEnv, uid: number | undefined): string {
  if (platform === "darwin") {
    const base = env.TMPDIR;
    if (base === undefined || !isSafeAbsolutePath(base)) throw new Error("TMPDIR must be a safe absolute path");
    return join(base, "herdr-a2a");
  }
  if (platform === "linux") {
    const base = env.XDG_RUNTIME_DIR;
    if (base !== undefined && base.length > 0) {
      if (!isSafeAbsolutePath(base)) throw new Error("XDG_RUNTIME_DIR must be a safe absolute path");
      return join(base, "herdr-a2a");
    }
    if (uid === undefined) throw new Error("the current user ID is required");
    return `/tmp/herdr-a2a-${uid}`;
  }
  throw new Error(`unsupported platform: ${platform}`);
}

function isSafeAbsolutePath(path: string): boolean {
  return isAbsolute(path)
    && path.length > 0
    && !path.includes("\0")
    && !path.split(/[\\/]/u).some((component) => component === "." || component === "..");
}

function isValidWorkspaceId(value: string | undefined): value is string {
  return value !== undefined
    && value.length > 0
    && Buffer.byteLength(value, "utf8") <= MAX_WORKSPACE_ID_BYTES
    && !/\p{Cc}/u.test(value);
}

async function validatePrivatePath(
  path: string,
  kind: "file" | "directory",
  requiredMode: number,
  uid: number | undefined,
): Promise<void> {
  const metadata = await lstat(path, { bigint: true });
  const correctKind = kind === "file" ? metadata.isFile() : metadata.isDirectory();
  if (!correctKind || metadata.isSymbolicLink()) throw new Error(`runtime ${kind} is unsafe`);
  if ((metadata.mode & 0o777n) !== BigInt(requiredMode)) throw new Error(`runtime ${kind} permissions are unsafe`);
  if (uid !== undefined && metadata.uid !== BigInt(uid)) throw new Error(`runtime ${kind} has the wrong owner`);
}

async function openProtectedRuntimeRoot(root: string, uid: number): Promise<FileHandle> {
  const parentPath = dirname(root);
  if (!isSafeAbsolutePath(parentPath)) throw new Error("runtime parent path is unsafe");
  const parentBefore = await lstat(parentPath, { bigint: true });
  const parent = await open(
    parentPath,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const parentOpened = await parent.stat({ bigint: true });
    validateRuntimeParent(parentPath, parentOpened, uid);
    if (!sameIdentity(parentBefore, parentOpened)) throw new Error("runtime parent path identity changed");
  } finally {
    await parent.close();
  }

  const rootBefore = await lstat(root, { bigint: true });
  await validatePrivatePath(root, "directory", 0o700, uid);
  const handle = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const opened = await handle.stat({ bigint: true });
  try {
    validatePrivateMetadata(opened, "directory", 0o700, uid);
    if (!sameIdentity(rootBefore, opened)) throw new Error("runtime directory path identity changed");
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function readProtectedDescriptor(
  path: string,
  root: string,
  rootHandle: FileHandle,
  uid: number,
): Promise<RuntimeDescriptor> {
  const before = await lstat(path, { bigint: true });
  validatePrivateMetadata(before, "file", 0o600, uid);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = await handle.stat({ bigint: true });
    validatePrivateMetadata(metadata, "file", 0o600, uid);
    if (!sameIdentity(before, metadata)) throw new Error("runtime descriptor path identity changed");
    if (metadata.size > BigInt(MAX_DESCRIPTOR_BYTES)) {
      throw new Error("runtime descriptor is invalid or too large");
    }
    const encoded = await readBounded(handle, MAX_DESCRIPTOR_BYTES);
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
    const after = await lstat(path, { bigint: true });
    if (!sameIdentity(metadata, after)) throw new Error("runtime descriptor path identity changed");
    const rootAfter = await lstat(root, { bigint: true });
    const openedRoot = await rootHandle.stat({ bigint: true });
    if (!sameIdentity(rootAfter, openedRoot)) throw new Error("runtime directory path identity changed");
    return JSON.parse(decoded) as RuntimeDescriptor;
  } finally {
    await handle.close();
  }
}

function validateRuntimeParent(path: string, metadata: BigIntStats, uid: number): void {
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("runtime parent is unsafe");
  const mode = metadata.mode & 0o7777n;
  if (metadata.uid === BigInt(uid)) {
    if ((mode & 0o022n) !== 0n) throw new Error("runtime parent permissions are unsafe");
    return;
  }
  if (metadata.uid === 0n) {
    if ((mode & 0o022n) !== 0n && (mode & 0o1000n) === 0n) {
      throw new Error("runtime parent permissions are unsafe");
    }
    return;
  }
  throw new Error("runtime parent has the wrong owner");
}

function validatePrivateMetadata(
  metadata: BigIntStats,
  kind: "file" | "directory",
  requiredMode: number,
  uid: number,
): void {
  const correctKind = kind === "file" ? metadata.isFile() : metadata.isDirectory();
  if (!correctKind || metadata.isSymbolicLink()) throw new Error(`runtime ${kind} is unsafe`);
  if ((metadata.mode & 0o777n) !== BigInt(requiredMode)) throw new Error(`runtime ${kind} permissions are unsafe`);
  if (metadata.uid !== BigInt(uid)) throw new Error(`runtime ${kind} has the wrong owner`);
}

export interface FileIdentity {
  dev: bigint;
  ino: bigint;
}

export function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

const sameIdentity = sameFileIdentity;

async function readBounded(handle: FileHandle, maximumBytes: number): Promise<Buffer> {
  const encoded = Buffer.allocUnsafe(maximumBytes + 1);
  let total = 0;
  while (total < encoded.length) {
    const { bytesRead } = await handle.read(encoded, total, encoded.length - total, null);
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  if (total > maximumBytes) throw new Error("runtime descriptor is invalid or too large");
  return encoded.subarray(0, total);
}

function realAndEffectiveCredentialsMatch(): boolean {
  const realUid = process.getuid?.();
  const effectiveUid = process.geteuid?.();
  const realGid = process.getgid?.();
  const effectiveGid = process.getegid?.();
  return realUid !== undefined
    && effectiveUid !== undefined
    && realGid !== undefined
    && effectiveGid !== undefined
    && realUid === effectiveUid
    && realGid === effectiveGid;
}

async function checkExecutableAccess(path: string): Promise<void> {
  await access(path, constants.X_OK);
}

function throwIfAborted(signal: AbortSignal | undefined, message: string): void {
  if (signal?.aborted === true) throw new Error(message);
}

async function awaitWithAbort<T>(
  pending: Promise<T>,
  signal: AbortSignal | undefined,
  message: string,
): Promise<T> {
  throwIfAborted(signal, message);
  if (signal === undefined) return pending;
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(new Error(message));
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) {
      abort();
      return;
    }
    pending.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

async function abortableDelay(
  milliseconds: number,
  signal: AbortSignal | undefined,
  message: string,
): Promise<void> {
  throwIfAborted(signal, message);
  if (signal === undefined) {
    await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    const abort = (): void => {
      clearTimeout(timer);
      reject(new Error(message));
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

function validateDescriptor(
  value: RuntimeDescriptor,
  sessionKey: string,
  workspaceId: string,
): void {
  if (!isRecord(value)) throw new Error("runtime descriptor must be an object");
  const keys = Object.keys(value).sort();
  const expected = [
    "base_url",
    "bearer_token",
    "broker_instance_id",
    "broker_pid",
    "created_unix_ms",
    "executable_path",
    "session_key",
    "workspace_id",
  ];
  if (JSON.stringify(keys) !== JSON.stringify(expected)
    || value.session_key !== sessionKey
    || value.workspace_id !== workspaceId) {
    throw new Error("runtime descriptor has an invalid shape, session identity, or workspace identity");
  }
  if (typeof value.base_url !== "string" || !isCanonicalLoopbackOrigin(value.base_url)) {
    throw new Error("runtime descriptor base URL must be a canonical loopback HTTP origin");
  }
  if (typeof value.bearer_token !== "string" || !isCanonicalToken(value.bearer_token)) {
    throw new Error("runtime descriptor bearer token must canonically encode 256 bits");
  }
  if (typeof value.broker_instance_id !== "string"
    || !isCanonicalInstanceId(value.broker_instance_id)) {
    throw new Error("runtime descriptor broker instance ID must canonically encode 256 bits");
  }
  if (typeof value.executable_path !== "string" || !isSafeAbsolutePath(value.executable_path)) {
    throw new Error("runtime descriptor executable path is invalid");
  }
  if (!Number.isSafeInteger(value.broker_pid)
    || value.broker_pid <= 0
    || value.broker_pid > MAX_PLATFORM_PID) {
    throw new Error("runtime descriptor broker PID is not representable");
  }
  if (!Number.isSafeInteger(value.created_unix_ms)
    || value.created_unix_ms <= 0
    || value.created_unix_ms > Date.now() + MAX_FUTURE_DESCRIPTOR_MS) {
    throw new Error("runtime descriptor creation timestamp is not sensible");
  }
}

function isCanonicalLoopbackOrigin(value: string): boolean {
  const match = /^http:\/\/127\.0\.0\.1:(\d{1,5})$/u.exec(value);
  if (match === null) return false;
  const port = Number(match[1]);
  return Number.isInteger(port)
    && port > 0
    && port <= 65_535
    && value === `http://127.0.0.1:${port}`;
}

function isCanonicalToken(value: string): boolean {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function isCanonicalInstanceId(value: string): boolean {
  return value.length === 43 && isCanonicalToken(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
