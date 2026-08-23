#!/usr/bin/env bash
set -euo pipefail

command -v node >/dev/null 2>&1 || {
  printf '%s\n' 'pi-smoke: Node is required.' >&2
  exit 1
}

self_test=0
if [[ "${1:-}" == "--self-test" ]]; then
  self_test=1
  shift
fi
if (( $# != 0 )); then
  printf '%s\n' 'pi-smoke: usage: pi-smoke.sh [--self-test]' >&2
  exit 1
fi

if (( self_test == 0 )) && [[ "${HERDR_ENV:-}" != "1" ]]; then
  printf '%s\n' 'pi-smoke: HERDR_ENV=1 is required; run this inside a Herdr pane.' >&2
  exit 1
fi

if (( self_test == 0 )) && [[ -z "${HERDR_SOCKET_PATH:-}" ]]; then
  printf '%s\n' 'pi-smoke: HERDR_SOCKET_PATH is required.' >&2
  exit 1
fi

if (( self_test == 0 )) && [[ -z "${HERDR_BIN_PATH:-}" || ! -x "$HERDR_BIN_PATH" ]]; then
  printf '%s\n' 'pi-smoke: executable HERDR_BIN_PATH is required.' >&2
  exit 1
fi

if (( self_test == 0 )); then
  herdr_version="$("$HERDR_BIN_PATH" --version 2>/dev/null)" || {
    printf '%s\n' 'pi-smoke: HERDR_BIN_PATH --version failed.' >&2
    exit 1
  }
  if [[ ! "$herdr_version" =~ ([0-9]+)\.([0-9]+)\.([0-9]+)([-+][0-9A-Za-z.-]+)? ]]; then
    printf '%s\n' 'pi-smoke: HERDR_BIN_PATH did not report a semantic version.' >&2
    exit 1
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  suffix="${BASH_REMATCH[4]:-}"
  if (( major == 0 && minor < 8 )) \
    || { (( major == 0 && minor == 8 && patch == 0 )) && [[ "$suffix" == -* ]]; }; then
    printf '%s\n' "pi-smoke: Herdr 0.8.0 or newer is required; found $herdr_version." >&2
    exit 1
  fi
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export HERDR_A2A_SESSION_CLIENT_PATH="$script_dir/../integrations/pi/src/session-client.ts"
export HERDR_A2A_SMOKE_SELF_TEST="$self_test"

exec node --input-type=module <<'NODE'
import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

function abort(message) {
  throw new Error(`pi-smoke: ${message}`);
}

function fakeGuardedHerdrBackend(command, args, options) {
  const invocation = args.join(" ");
  if (/^(?:agent prompt|pane send-text|pane send-keys)(?: |$)/u.test(invocation)) {
    abort(`terminal-input Herdr argv was attempted: ${invocation}`);
  }
  if (args.length !== 2 || args[0] !== "agent" || args[1] !== "list") {
    abort(`unexpected Herdr argv was attempted: ${invocation}`);
  }
  return {
    status: 0,
    stdout: JSON.stringify({ result: { agents: [] } }),
    stderr: "",
  };
}

function runHerdrAgentList(backend = spawnSync) {
  return backend(process.env.HERDR_BIN_PATH, ["agent", "list"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function requireRecord(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    abort(`${label} has an invalid shape`);
  }
  return value;
}

function parseAgentDirectory(value) {
  const envelope = requireRecord(value, "agent list response");
  if (Object.keys(envelope).length !== 1 || !Array.isArray(envelope.agents)) {
    abort("agent list response has an invalid shape");
  }
  const canonicalNames = new Set();
  return envelope.agents.map((value) => {
    const agent = requireRecord(value, "registered agent");
    const keys = Object.keys(agent).sort();
    const expectedKeys = ["canonical_name", "harness", "pane_id", "role", "status"];
    if (keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])) {
      abort("registered agent has an invalid shape");
    }
    if (typeof agent.canonical_name !== "string"
      || !/^[a-z][a-z0-9-]{1,31}$/u.test(agent.canonical_name)
      || canonicalNames.has(agent.canonical_name)
      || typeof agent.role !== "string"
      || Buffer.byteLength(agent.role, "utf8") === 0
      || Buffer.byteLength(agent.role, "utf8") > 256
      || /[\u0000-\u001f\u007f-\u009f]/u.test(agent.role)
      || typeof agent.pane_id !== "string"
      || agent.pane_id.length === 0
      || Buffer.byteLength(agent.pane_id, "utf8") > 1024
      || /[\u0000-\u001f\u007f-\u009f]/u.test(agent.pane_id)
      || agent.harness !== "pi"
      || agent.status !== "live") {
      abort("registered agent has invalid fields");
    }
    canonicalNames.add(agent.canonical_name);
    return agent;
  }).sort((left, right) => left.canonical_name.localeCompare(right.canonical_name));
}

function validateBrokerInstanceId(value) {
  if (typeof value !== "string"
    || value.length !== 43
    || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    abort("runtime descriptor broker instance ID is invalid");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== value) {
    abort("runtime descriptor broker instance ID is invalid");
  }
}

function validateHealthProof({
  descriptorInstance,
  bearerToken,
  nonceBytes,
  responseInstance,
  encodedProof,
}) {
  if (responseInstance !== descriptorInstance
    || typeof encodedProof !== "string"
    || encodedProof.length !== 43
    || !/^[A-Za-z0-9_-]+$/u.test(encodedProof)) {
    abort("broker identity proof headers were invalid");
  }
  const proof = Buffer.from(encodedProof, "base64url");
  if (proof.length !== 32 || proof.toString("base64url") !== encodedProof) {
    abort("broker identity proof encoding was invalid");
  }
  const key = createHash("sha256").update(bearerToken).digest();
  const expectedProof = createHmac("sha256", key)
    .update("herdr-a2a-proof-v2\0")
    .update(descriptorInstance)
    .update(nonceBytes)
    .digest();
  if (!timingSafeEqual(proof, expectedProof)) abort("broker identity proof was invalid");
}

function healthProof(bearerToken, brokerInstanceId, nonceBytes) {
  const key = createHash("sha256").update(bearerToken).digest();
  return createHmac("sha256", key)
    .update("herdr-a2a-proof-v2\0")
    .update(brokerInstanceId)
    .update(nonceBytes)
    .digest("base64url");
}

if (process.env.HERDR_A2A_SMOKE_SELF_TEST === "1") {
  const brokerInstanceId = Buffer.alloc(32, 1).toString("base64url");
  const oldBrokerInstanceId = Buffer.alloc(32, 2).toString("base64url");
  const bearerToken = Buffer.alloc(32, 3).toString("base64url");
  const nonceBytes = Buffer.alloc(32, 4);
  validateBrokerInstanceId(brokerInstanceId);
  for (const invalid of [
    undefined,
    "",
    Buffer.alloc(31, 1).toString("base64url"),
    `${Buffer.alloc(32, 1).toString("base64url")}=`,
    `${Buffer.alloc(32, 1).toString("base64url").slice(0, -1)}+`,
    Buffer.alloc(33, 1).toString("base64url"),
  ]) {
    let rejected = false;
    try {
      validateBrokerInstanceId(invalid);
    } catch {
      rejected = true;
    }
    if (!rejected) abort(`self-test accepted invalid instance ID: ${String(invalid)}`);
  }
  validateHealthProof({
    descriptorInstance: brokerInstanceId,
    bearerToken,
    nonceBytes,
    responseInstance: brokerInstanceId,
    encodedProof: healthProof(bearerToken, brokerInstanceId, nonceBytes),
  });
  for (const invalid of [
    {
      responseInstance: oldBrokerInstanceId,
      encodedProof: healthProof(bearerToken, oldBrokerInstanceId, nonceBytes),
    },
    {
      responseInstance: brokerInstanceId,
      encodedProof: healthProof(bearerToken, oldBrokerInstanceId, nonceBytes),
    },
  ]) {
    let rejected = false;
    try {
      validateHealthProof({
        descriptorInstance: brokerInstanceId,
        bearerToken,
        nonceBytes,
        ...invalid,
      });
    } catch {
      rejected = true;
    }
    if (!rejected) abort("self-test accepted proof from an old broker instance");
  }
  const directory = parseAgentDirectory({
    agents: [
      {
        canonical_name: "reviewer-abcde",
        role: "reviewer",
        pane_id: "%1:p2",
        harness: "pi",
        status: "live",
      },
      {
        canonical_name: "implementer-fghij",
        role: "implementer",
        pane_id: "%1:p1",
        harness: "pi",
        status: "live",
      },
    ],
  });
  if (directory.map((agent) => agent.role).join(",") !== "implementer,reviewer") {
    abort("self-test did not parse exact directory records");
  }
  const maximumDirectory = parseAgentDirectory({
    agents: [{
      canonical_name: "abcdefghijklmnopqrstuvwxy-abcdef",
      role: "maximum canonical",
      pane_id: "%1:p3",
      harness: "pi",
      status: "live",
    }],
  });
  if (Buffer.byteLength(maximumDirectory[0].canonical_name, "utf8") !== 32) {
    abort("self-test rejected a valid 32-byte canonical name");
  }
  for (const invalid of [
    { agents: [{ ...directory[0], agent_name: directory[0].canonical_name }] },
    { agents: [{ ...directory[0], canonical_name: "../implementer" }] },
    { agents: [{ ...directory[0] }, { ...directory[0] }] },
  ]) {
    let rejected = false;
    try {
      parseAgentDirectory(invalid);
    } catch {
      rejected = true;
    }
    if (!rejected) abort("self-test accepted an invalid agent directory");
  }
  const guarded = runHerdrAgentList(fakeGuardedHerdrBackend);
  if (guarded.status !== 0 || JSON.parse(guarded.stdout).result.agents.length !== 0) {
    abort("self-test fake Herdr backend rejected the read-only directory call");
  }
  for (const forbidden of [
    ["agent", "prompt", "w1:p1", "peer text"],
    ["pane", "send-text", "w1:p1", "peer text"],
    ["pane", "send-keys", "w1:p1", "Enter"],
  ]) {
    let rejected = false;
    try {
      fakeGuardedHerdrBackend("herdr", forbidden, {});
    } catch {
      rejected = true;
    }
    if (!rejected) abort(`self-test accepted terminal-input argv: ${forbidden.join(" ")}`);
  }
  console.log("pi-smoke self-test passed");
  process.exit(0);
}

const sessionClientUrl = pathToFileURL(process.env.HERDR_A2A_SESSION_CLIENT_PATH);
const { loadRuntimeDescriptor } = await import(sessionClientUrl.href);
const descriptor = await loadRuntimeDescriptor();
validateBrokerInstanceId(descriptor.broker_instance_id);
const baseUrl = new URL(descriptor.base_url);

const nonceBytes = randomBytes(32);
const nonce = nonceBytes.toString("base64url");
const proofUrl = new URL(`/health/proof/${nonce}`, baseUrl);
const proofResponse = await fetch(proofUrl, {
  redirect: "error",
  signal: AbortSignal.timeout(2_000),
});
if (!proofResponse.ok || proofResponse.url !== proofUrl.href) {
  abort("broker identity proof was rejected");
}
const responseInstance = proofResponse.headers.get("x-herdr-a2a-instance");
const encodedProof = proofResponse.headers.get("x-herdr-a2a-health-proof");
validateHealthProof({
  descriptorInstance: descriptor.broker_instance_id,
  bearerToken: descriptor.bearer_token,
  nonceBytes,
  responseInstance,
  encodedProof,
});

async function brokerJson(path) {
  const signal = AbortSignal.timeout(2_000);
  const response = await fetch(new URL(path, baseUrl), {
    headers: { authorization: `Bearer ${descriptor.bearer_token}` },
    redirect: "error",
    signal,
  });
  if (!response.ok) abort(`${path} returned HTTP ${response.status}`);
  return requireRecord(await response.json(), path);
}

const health = await brokerJson("/health");
if (health.status !== "ok") abort("broker health response was not ok");
console.log("Broker health: ok");

const brokerAgents = await brokerJson("/v1/agents");
const registeredAgents = parseAgentDirectory(brokerAgents);
console.log(`A2A registered agents: ${registeredAgents.length === 0
  ? "(none)"
  : registeredAgents.map((agent) => `${agent.role} · ${agent.canonical_name}`).join(", ")}`);

const herdrResult = runHerdrAgentList();
if (herdrResult.status !== 0) abort(`herdr agent list failed: ${herdrResult.stderr.trim()}`);
const herdrEnvelope = requireRecord(JSON.parse(herdrResult.stdout), "Herdr agent list");
const herdrAgents = requireRecord(herdrEnvelope.result, "Herdr result").agents;
if (!Array.isArray(herdrAgents)) abort("Herdr agent list has an invalid shape");
const piAgents = herdrAgents
  .map((agent) => requireRecord(agent, "Herdr agent"))
  .filter((agent) => agent.agent === "pi");
console.log(`Herdr Pi agents: ${piAgents.length === 0
  ? "(none)"
  : piAgents.map((agent) => `${agent.pane_id}=${agent.name ?? "<unnamed>"}`).join(", ")}`);

const requiredNames = ["implementer", "reviewer"];
const currentNames = new Set(piAgents.map((agent) => agent.name));
const missingNames = requiredNames.filter((name) => !currentNames.has(name));
if (missingNames.length > 0) {
  const unnamed = piAgents.filter((agent) => agent.name == null && typeof agent.pane_id === "string");
  console.error("Name the two Pi agents, then restart their Pi sessions so they register:");
  for (const [index, name] of missingNames.entries()) {
    const target = unnamed[index]?.pane_id ?? `<${name}-pane-id>`;
    console.error(`herdr agent rename ${target} ${name}`);
  }
  process.exitCode = 1;
} else {
  const missingRegistrations = requiredNames.filter(
    (name) => registeredAgents.filter((agent) => agent.role === name).length === 0,
  );
  if (missingRegistrations.length > 0) {
    abort(`named Pi agent(s) not registered with A2A: ${missingRegistrations.join(", ")}`);
  }
  for (const name of requiredNames) {
    const candidates = registeredAgents.filter((agent) => agent.role === name);
    if (candidates.length > 1) {
      abort(`named Pi agent is ambiguous in A2A: ${name} (${candidates
        .map((agent) => agent.canonical_name)
        .join(", ")})`);
    }
  }
  console.log("Smoke diagnostics passed; no terminal input was sent.");
}
NODE
