import type { ExtensionCommandContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const ROLE_PATTERN = "^[a-z][a-z0-9_-]{0,31}$";
const ROLE_REGEXP = /^[a-z][a-z0-9_-]{0,31}$/u;
const MAX_TEAM_MEMBERS = 8;

export type HerdrA2ACommand =
  | { kind: "help" }
  | { kind: "status" }
  | { kind: "doctor" }
  | { kind: "uninstall"; purge: boolean }
  | { kind: "team"; selfRole?: string; roles: string[] };

type CallClient = (
  method: string,
  params: Record<string, unknown>,
  signal?: AbortSignal,
) => Promise<unknown>;

const roleSchema = Type.String({
  minLength: 1,
  maxLength: 32,
  pattern: ROLE_PATTERN,
  description: "Lowercase workspace role for one explicitly requested Pi pane.",
});

export function parseHerdrA2ACommand(input: string): HerdrA2ACommand {
  const tokens = input.trim().split(/\s+/u).filter(Boolean);
  if (tokens.length === 0 || (tokens.length === 1 && tokens[0] === "help")) {
    return { kind: "help" };
  }
  if (tokens.length === 1 && tokens[0] === "status") return { kind: "status" };
  if (tokens.length === 1 && tokens[0] === "doctor") return { kind: "doctor" };
  if (tokens[0] === "uninstall") {
    if (tokens.length === 1) return { kind: "uninstall", purge: false };
    if (tokens.length === 2 && tokens[1] === "--purge") {
      return { kind: "uninstall", purge: true };
    }
    throw new Error("usage: /herdr-a2a uninstall [--purge]");
  }
  if (tokens.shift() !== "team") throw new Error("unknown /herdr-a2a command");

  let selfRole: string | undefined;
  const roles: string[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token === "--self") {
      if (selfRole !== undefined) throw new Error("--self may be supplied only once");
      const candidate = tokens[index + 1];
      if (candidate === undefined || candidate.startsWith("--")) {
        throw new Error("--self requires a role");
      }
      selfRole = candidate;
      index += 1;
    } else {
      if (token.startsWith("--")) throw new Error(`unknown team option: ${token}`);
      roles.push(token);
    }
  }
  validateTeamRoles(roles, selfRole);
  return { kind: "team", ...(selfRole === undefined ? {} : { selfRole }), roles };
}

export function completeHerdrA2AArgs(prefix: string) {
  const candidates = ["team", "status", "doctor", "uninstall", "help"];
  const token = prefix.trimStart();
  if (token.includes(" ")) return null;
  const matches = candidates.filter((candidate) => candidate.startsWith(token));
  return matches.length === 0
    ? null
    : matches.map((value) => ({ value, label: value }));
}

export async function runHerdrA2ACommand(
  command: string | HerdrA2ACommand,
  callClient: CallClient,
  signal?: AbortSignal,
): Promise<{ text: string; details?: unknown }> {
  const parsed = typeof command === "string" ? parseHerdrA2ACommand(command) : command;
  if (parsed.kind === "help") {
    return {
      text: "/herdr-a2a team [--self role] role [role ...]\n/herdr-a2a status\n/herdr-a2a doctor\n/herdr-a2a uninstall [--purge]\n/herdr-a2a help",
    };
  }
  if (parsed.kind === "status") {
    const value = await callClient("status", {}, signal);
    return { text: renderStatus(value), details: value };
  }
  if (parsed.kind === "doctor") {
    const value = await callClient("doctor", {}, signal);
    return { text: renderDoctor(value), details: value };
  }
  if (parsed.kind === "uninstall") {
    const value = await callClient("managed_remove", { purge: parsed.purge }, signal);
    if (!isRecord(value)
      || !hasExactKeys(value, ["state", "retained_data"])
      || value.state !== "removed"
      || typeof value.retained_data !== "boolean"
      || value.retained_data !== !parsed.purge) {
      throw new Error("invalid managed removal result");
    }
    return {
      text: parsed.purge
        ? "Herdr A2A was removed and retained workspace data was purged."
        : "Herdr A2A was removed. Workspace databases and logs were retained for reinstall recovery.",
      details: value,
    };
  }
  const value = await callClient("create_team", {
    roles: parsed.roles,
    ...(parsed.selfRole === undefined ? {} : { self_role: parsed.selfRole }),
  }, signal);
  return { text: renderTeamDirectory(value, parsed.roles), details: value };
}

function renderStatus(value: unknown): string {
  if (!isRecord(value)
    || !hasExactKeys(value, [
      "workspace_id", "broker", "storage", "registrations", "agents", "tasks", "last_event",
    ])
    || !isSafeString(value.workspace_id, 1_024)
    || value.broker !== "healthy"
    || value.storage !== "reconciled"
    || !isCount(value.registrations)
    || !Array.isArray(value.agents)
    || !isRecord(value.tasks)
    || !hasExactKeys(value.tasks, ["queued", "leased", "waiting_reply", "terminal"])
    || !Object.values(value.tasks).every(isCount)
    || value.agents.length > value.registrations) {
    throw new Error("invalid redacted Herdr status");
  }
  const seen = new Set<string>();
  const agents = value.agents.map((candidate) => {
    if (!isRecord(candidate)
      || !hasExactKeys(candidate, ["role", "canonical_name", "status"])
      || !isSafeString(candidate.role, 256)
      || typeof candidate.canonical_name !== "string"
      || !ROLE_REGEXP.test(candidate.canonical_name)
      || candidate.status !== "connected"
      || seen.has(candidate.canonical_name)) {
      throw new Error("invalid redacted Herdr status");
    }
    seen.add(candidate.canonical_name);
    return `${candidate.role} · ${candidate.canonical_name} · connected`;
  });
  if (value.last_event !== null) {
    if (!isRecord(value.last_event)
      || !hasExactKeys(value.last_event, ["kind", "canonical_name", "unix_time"])
      || typeof value.last_event.kind !== "string"
      || !/^[a-z][a-z_]{0,63}$/u.test(value.last_event.kind)
      || typeof value.last_event.canonical_name !== "string"
      || !ROLE_REGEXP.test(value.last_event.canonical_name)
      || !Number.isSafeInteger(value.last_event.unix_time)) {
      throw new Error("invalid redacted Herdr status");
    }
  }
  const tasks = value.tasks as Record<string, number>;
  return [
    `Herdr A2A · workspace: ${value.workspace_id}`,
    `Broker ${value.broker} · Storage ${value.storage}`,
    ...agents,
    `queued ${tasks.queued} · leased ${tasks.leased} · waiting reply ${tasks.waiting_reply} · terminal ${tasks.terminal}`,
  ].join("\n");
}

function renderDoctor(value: unknown): string {
  if (!isRecord(value)
    || !hasExactKeys(value, ["overall", "checks"])
    || !["healthy", "warning", "failed"].includes(String(value.overall))
    || !Array.isArray(value.checks)
    || value.checks.length === 0) {
    throw new Error("invalid Herdr Doctor report");
  }
  const checks = value.checks.map((candidate) => {
    if (!isRecord(candidate)
      || !hasExactKeys(candidate, ["code", "state", "summary"])
      || typeof candidate.code !== "string"
      || !/^[a-z][a-z0-9_]{0,63}$/u.test(candidate.code)
      || !["healthy", "warning", "failed"].includes(String(candidate.state))
      || !isSafeString(candidate.summary, 512)) {
      throw new Error("invalid Herdr Doctor report");
    }
    return `${candidate.state} · ${candidate.code} · ${candidate.summary}`;
  });
  return [`Doctor ${value.overall}`, ...checks].join("\n");
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export async function runHerdrA2ASlashCommand(
  args: string,
  context: ExtensionCommandContext,
  callClient: CallClient,
): Promise<void> {
  const parsed = parseHerdrA2ACommand(args);
  if (parsed.kind === "uninstall") {
    const confirmed = await context.ui.confirm(
      "Remove Herdr A2A?",
      "This removes the managed Pi adapter and Herdr plugin. Workspace databases and logs are retained unless you requested --purge.",
    );
    if (!confirmed) return;
    if (parsed.purge) {
      const purgeConfirmed = await context.ui.confirm(
        "Permanently purge Herdr A2A data?",
        "This permanently deletes retained workspace databases, logs, and identity state. This cannot be undone.",
      );
      if (!purgeConfirmed) return;
    }
  }
  const result = await runHerdrA2ACommand(parsed, callClient, context.signal);
  context.ui.notify(result.text, "info");
}

export function createTeamTool(callClient: CallClient): ToolDefinition {
  return {
    name: "a2a_create_team",
    label: "Create Herdr Team",
    description: "Create exactly the explicitly user-authorized Pi teammate panes in this workspace.",
    parameters: Type.Object({
      roles: Type.Array(roleSchema, {
        minItems: 1,
        maxItems: MAX_TEAM_MEMBERS,
        uniqueItems: true,
      }),
      self_role: Type.Optional(roleSchema),
    }, { additionalProperties: false }),
    async execute(_toolCallId, params, signal) {
      const request = validateTeamParams(params as Record<string, unknown>);
      const value = await callClient("create_team", request, signal);
      return {
        content: [{
          type: "text" as const,
          text: renderTeamDirectory(value, request.roles),
        }],
        details: value,
      };
    },
  };
}

function validateTeamParams(params: Record<string, unknown>): {
  roles: string[];
  self_role?: string;
} {
  if (!Array.isArray(params.roles)
    || !params.roles.every((role): role is string => typeof role === "string")) {
    throw new Error("roles must be an array of bounded role labels");
  }
  const selfRole = params.self_role;
  if (selfRole !== undefined && typeof selfRole !== "string") {
    throw new Error("self_role must be a bounded role label");
  }
  validateTeamRoles(params.roles, selfRole);
  return {
    roles: [...params.roles],
    ...(selfRole === undefined ? {} : { self_role: selfRole }),
  };
}

function validateTeamRoles(roles: string[], selfRole?: string): void {
  if (roles.length < 1 || roles.length > MAX_TEAM_MEMBERS) {
    throw new Error("team requires between one and eight roles");
  }
  const all = selfRole === undefined ? roles : [selfRole, ...roles];
  if (all.some((role) => !ROLE_REGEXP.test(role))) {
    throw new Error("roles must match [a-z][a-z0-9_-]{0,31}");
  }
  if (new Set(all).size !== all.length) throw new Error("team roles must be unique");
}

function renderTeamDirectory(value: unknown, requestedRoles: readonly string[]): string {
  if (!isRecord(value)
    || !hasExactKeys(value, ["members"])
    || !Array.isArray(value.members)
    || value.members.length !== requestedRoles.length) {
    throw new Error("invalid Herdr team result");
  }
  const seenRoles = new Set<string>();
  const seenPanes = new Set<string>();
  const seenCanonical = new Set<string>();
  return value.members.map((candidate, index) => {
    if (!isRecord(candidate)
      || !hasExactKeys(candidate, [
        "requested_role",
        "pane_id",
        "canonical_name",
        "state",
        "error_code",
      ])
      || typeof candidate.requested_role !== "string"
      || !ROLE_REGEXP.test(candidate.requested_role)
      || candidate.requested_role !== requestedRoles[index]
      || seenRoles.has(candidate.requested_role)
      || (candidate.pane_id !== null
        && !isSafeString(candidate.pane_id, 1_024))
      || (candidate.canonical_name !== null
        && (typeof candidate.canonical_name !== "string"
          || !ROLE_REGEXP.test(candidate.canonical_name)))
      || !["started", "registered", "timed_out", "failed"].includes(
        String(candidate.state),
      )
      || (candidate.error_code !== null
        && (typeof candidate.error_code !== "string"
          || !/^[a-z][a-z0-9_]{0,63}$/u.test(candidate.error_code)))
      || (candidate.state === "registered"
        && (candidate.pane_id === null || candidate.canonical_name === null))
      || (typeof candidate.pane_id === "string" && seenPanes.has(candidate.pane_id))
      || (typeof candidate.canonical_name === "string"
        && seenCanonical.has(candidate.canonical_name))) {
      throw new Error("invalid Herdr team result");
    }
    seenRoles.add(candidate.requested_role);
    if (typeof candidate.pane_id === "string") seenPanes.add(candidate.pane_id);
    if (typeof candidate.canonical_name === "string") {
      seenCanonical.add(candidate.canonical_name);
    }
    const pane = typeof candidate.pane_id === "string" ? candidate.pane_id : "no pane";
    const canonical = typeof candidate.canonical_name === "string"
      ? candidate.canonical_name
      : candidate.state;
    return `${candidate.requested_role} · ${canonical} · ${pane}`;
  }).join("\n");
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function isSafeString(value: unknown, maxBytes: number): value is string {
  return typeof value === "string"
    && value.length > 0
    && Buffer.byteLength(value, "utf8") <= maxBytes
    && !/[\p{Cc}\u2028\u2029]/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
