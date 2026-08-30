# Herdr A2A

Install the plugin once:

```sh
herdr plugin install Liquescent-Development/herdr-a2a/plugins/herdr
```

That managed install verifies the native release, installs the Pi adapter, records exact
ownership, and runs Doctor. It does not start a broker or restart a Pi process. The next Pi
launched in a Herdr workspace loads the adapter automatically; the first valid bootstrap lazily
starts one hidden broker for that workspace, and later Pi processes join it automatically.

Pi is the only supported agent harness in this release. macOS and Linux are supported with Herdr
0.8.0 or newer and Pi on Node 22.19.0 or newer. Peer messages always enter model context through
the Pi extension and A2A protocol. They never use `agent prompt`, `pane send-text`, `pane
send-keys`, simulated Enter, or another terminal-input fallback.

## Peer workflow

Use ordinary language for an existing live peer. Pi resolves a unique live role and handles A2A
delivery without asking you to perform transport steps:

```text
Say pong to worker and ask for a ping back.
Dispatch the requested implementation to worker and return its result.
Ask reviewer to review commit <sha> and summarize the review.
```

If the role is ambiguous, Pi asks you to select a canonical identity. If it is missing, it reports
that fact and does not create a pane. Durable or security-sensitive work targets a canonical
identity. Peer work queues after a busy turn, and the receiver replies automatically; you never
need to request a manual receiver wake-up.

The Pi package also provides these A2A tools as an advanced/debugging reference:

- `a2a_list_agents`
- `a2a_send_message`
- `a2a_wait_for_message`
- `a2a_reply`
- `a2a_cancel_task`
- `a2a_create_team`

Role-only addressing is accepted only when exactly one live agent has that role. Use canonical
identities for retained tasks or other security-sensitive targeting.

## Create a team

From Pi, create one to eight teammate panes with a slash command:

```text
/herdr-a2a team worker reviewer
```

To rename the current pane as part of the same validated operation:

```text
/herdr-a2a team --self coordinator worker reviewer
```

The natural-language equivalent invokes the same bounded operation only when the request clearly
authorizes new panes. For example:

```text
Call yourself coordinator, launch a worker and reviewer in this workspace, and coordinate through A2A.
```

Installation, startup hooks, and vague requests to coordinate never create teammate panes. The
team operation validates all roles before mutation, preserves focus, and reports every created,
registered, failed, or timed-out pane. Roles match `[a-z][a-z0-9_-]{0,31}`. The directory shows a
mutable role, immutable canonical A2A identity, and opaque pane identity together. Durable tasks
bind to the canonical identity; renaming a role cannot retarget existing work.

## Status and Doctor

Use Pi for the common checks:

```text
/herdr-a2a status
/herdr-a2a doctor
```

The optional Herdr status popup is operational and redacted:

```sh
herdr plugin pane open --plugin herdr.a2a --entrypoint status --placement popup
```

Status and Doctor never expose bearer credentials, peer message bodies, raw descriptors, or full
task identifiers. Doctor checks managed versions and ownership, Pi configuration, workspace
storage, broker proof, registration, and safely repairable stale state. A Pi-absent install reports
`Pi adapter pending`; Doctor or the next Pi lifecycle event completes configuration after Pi is
installed, with activation on the following Pi launch.

The plugin, native binary, and Pi adapter must share one release version. The managed adapter
supports Pi `>=0.84.2` and Typebox `>=1.3.7 <1.4.0`; install checks this compatibility
before changing managed state, and Doctor reports the same exact ranges.

## Removal and recovery

The supported clean-removal path is:

```text
/herdr-a2a uninstall
```

Pi asks for confirmation, stops only authenticated plugin-owned workspace processes, removes the
exact recorded Pi entry and owned files, and unregisters `herdr.a2a` last. Durable workspace data,
logs, and identities remain available for reinstall. Permanent deletion is separate and asks for a
second confirmation:

```text
/herdr-a2a uninstall --purge
```

Herdr 0.8 has no plugin uninstall hook. If you instead run bare `herdr plugin uninstall
herdr.a2a`, the stable Pi shim becomes silent and inert on future launches, but already-running
processes and owned files may remain. Reinstall the plugin and use `/herdr-a2a uninstall` for a
clean retry.

Managed installation also leaves a mode-0600, source-only recovery notice outside the checkout:

- macOS: `~/Library/Application Support/herdr-a2a/rescue/uninstall.sh`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/herdr-a2a/rescue/uninstall.sh`

The notice is intentionally not executable. Sourcing it prints bounded recovery guidance and
never launches unproved code, signals a process, or mutates the filesystem. The authenticated
managed CLI recorded in `ownership.json` is the remover; if that binary is absent or fails exact
ownership validation, reinstall first so recovery can fail closed rather than deleting an
ambiguous target.

## How workspace A2A behaves

Each Herdr workspace receives independent credentials, descriptors, locks, storage, identities,
and tasks—even when two workspaces open the same repository. A broker crash does not eagerly start
another process. The next adapter bootstrap or A2A operation starts a replacement through the
workspace coordinator, and adapters recover within the original operation deadline. In-flight
task identity, exact-once delivery guarantees, and canonical identity survive broker restart.

The broker binds only loopback and requires a protected descriptor plus authenticated health
proof. Peer content remains untrusted agent-authored input. Logs stay quiet for normal message
traffic and do not contain message bodies, bearer tokens, or complete task identifiers.

## Development from source

Normal users do not need Rust, Cargo, npm, a visible broker pane, or a manual Pi install. For a
linked development checkout:

```sh
cargo build --release --workspace
herdr plugin link "$PWD/plugins/herdr"
herdr plugin action invoke herdr.a2a.setup-dev
```

`setup-dev` applies the same ownership checks as managed installation. Restart Pi after linking so
the adapter loads. The managed path downloads versioned release assets and never invokes Cargo or
npm.

Protocol development can run the binary directly, but this is not the normal workspace lifecycle:

```sh
cargo run -p herdr-a2a-cli -- --help
cargo run -p herdr-a2a-cli -- broker
```

Direct broker use requires the Herdr workspace environment documented by `--help`; the plugin
coordinator remains authoritative for managed workspace startup.

## Release verification

Release tags must be trusted SSH-signed tags named exactly `v<manifest-version>`. CI builds native
archives for:

- `aarch64-apple-darwin` → `herdr-a2a-0.1.9-macos-arm64.tar.gz`
- `x86_64-apple-darwin` → `herdr-a2a-0.1.9-macos-x86_64.tar.gz`
- `aarch64-unknown-linux-gnu` → `herdr-a2a-0.1.9-linux-arm64.tar.gz`
- `x86_64-unknown-linux-gnu` → `herdr-a2a-0.1.9-linux-x86_64.tar.gz`

Each target also publishes the same-stem bootstrap binary and SHA-256 files. Archives contain only
the stable binary, Pi package files, ownership metadata template, dispatch script, and source-only
rescue script, with normalized owners, modes, timestamps, ordering, and gzip metadata.

The repository acceptance gate is below. The Rust test runner uses a private dedicated target
directory and fixes the umask, test-thread count, and debug-info level required by the
security-sensitive fixtures. Set `HERDR_A2A_TEST_TARGET_DIR` to choose a different private target
directory.

```sh
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings
bash scripts/test-workspace.sh
npm --prefix integrations/pi test
npm --prefix integrations/pi run typecheck
bash -n plugins/herdr/scripts/install.sh
bash -n plugins/herdr/scripts/dispatch.sh
bash -n plugins/herdr/scripts/uninstall.sh
bash scripts/test-workspace-self-test.sh
bash scripts/managed-install-self-test.sh
bash scripts/uninstall-self-test.sh
bash scripts/package-release.sh --self-test
bash scripts/zero-config-smoke.sh --self-test
bash scripts/pi-smoke.sh --self-test
npm pack ./integrations/pi --dry-run
git diff --check
```

The live acceptance uses dedicated Herdr resources and records every opaque workspace, pane, agent,
task, and conversation ID before cleaning up only those dedicated resources.
