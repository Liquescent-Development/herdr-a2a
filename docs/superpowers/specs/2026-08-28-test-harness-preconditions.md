# Test Harness Preconditions Design

## Goal

Provide one reproducible workspace-test entry point that satisfies the security-sensitive Rust tests without weakening production validation.

## Root causes

The existing raw test command relies on three unstated or incompletely enforced harness conditions:

1. A caller umask of `0002` creates temporary directories as `0775`, which strict path validators correctly reject.
2. Tests in `operations.rs` mutate process-global environment and require `RUST_TEST_THREADS=1`.
3. Current toolchains produce debug executables larger than the managed-owned-file hashing limit; removing test debuginfo keeps the executable below the production bound.

## Design

Create `scripts/test-workspace.sh` as the canonical Rust workspace-test entry point. It will:

- set umask `0022`;
- force `CARGO_BUILD_JOBS=2` and `RUST_TEST_THREADS=1`;
- force `RUSTFLAGS=-C debuginfo=0` and clear encoded Rust flags so the size condition is deterministic;
- use a dedicated target directory at `${HERDR_A2A_TEST_TARGET_DIR:-$HOME/.herdr-a2a-test-target}`;
- reject a target-directory symlink and create or harden the target directory to mode `0700`;
- run `cargo test --workspace --all-features` from the repository root.

Add a shell self-test that executes a copied runner with a fake `cargo`, proving its command, environment, umask, and target permissions without compiling the workspace. Update the README acceptance gate to call the runner.

## Security constraints

- Do not weaken path, ownership, executable, descriptor, or hashing validation.
- Do not increase production file-size limits.
- Do not silently use caller-provided `CARGO_TARGET_DIR`, because its ancestry may be unsafe.
- Preserve fail-closed handling of symlink target directories.

## Additional full-suite defects

The canonical run exposed three independent baseline defects after the original harness preconditions were satisfied:

1. `persisted_paths_reject_line_breaks_and_non_utf8` changes `HOME`, but non-macOS managed storage uses `XDG_DATA_HOME` when the fixture supplies it. The regression must mutate the platform's actual persisted-root variable.
2. After an exact starting coordinator is killed, Linux can report its process proof absent slightly before every thread has released the coordinator flock. Lock acquisition must be retried only within the existing shared retirement deadline, followed by the existing exact lock-record validation.
3. Linux `kill -0` reports zombies as present. Test-only exact-process and process-group liveness helpers must treat zombie-only membership as retired, matching production's `/proc/<pid>/stat` proof semantics.
4. The Rust confirmed-task restart timeout assertion expects `broker_unavailable`, while the implementation and Pi integration contract classify a confirmed, reachable working task that exhausts its absolute deadline as `deadline_expired`. Align the stale Rust expectation without changing runtime behavior.

## Scope

This repair changes the canonical test harness, its regression self-test, the affected managed-install fixtures, and the bounded coordinator lock-release check. It does not weaken validation or extend any production deadline. AppleDouble files and managed startup registration behavior are out of scope.
