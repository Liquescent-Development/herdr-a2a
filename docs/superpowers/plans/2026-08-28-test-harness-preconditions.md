# Test Harness Preconditions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible canonical Rust workspace-test runner that enforces all security-sensitive harness preconditions.

**Architecture:** A small Bash runner owns process configuration and invokes the unchanged Cargo suite. A hermetic shell self-test replaces `cargo` with a recording executable and verifies the runner's externally observable contract.

**Tech Stack:** Bash, Cargo, GNU/BSD `stat` compatibility via a Python assertion helper in the self-test, Markdown.

**Spec:** `docs/superpowers/specs/2026-08-28-test-harness-preconditions.md`

## Global Constraints

- Do not weaken path, ownership, executable, descriptor, or hashing validation.
- Do not increase production file-size limits.
- The canonical runner must set umask `0022`, `CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=1`, and `RUSTFLAGS=-C debuginfo=0`.
- The dedicated target directory must be a non-symlink directory with mode `0700`.
- Run `cargo test --workspace --all-features` from the repository root.

---

### Task 1: Canonical workspace-test runner

**Files:**
- Create: `scripts/test-workspace.sh`
- Create: `scripts/test-workspace-self-test.sh`
- Modify: `README.md:184-190`
- Reference: `docs/superpowers/specs/2026-08-28-test-harness-preconditions.md`

**Interfaces:**
- Consumes: optional `HERDR_A2A_TEST_TARGET_DIR`; otherwise `$HOME/.herdr-a2a-test-target`.
- Produces: executable `scripts/test-workspace.sh` and a zero-exit self-test.

- [ ] **Step 1: Write the failing shell self-test**

Create a hermetic temporary repository containing a copied runner path and fake `cargo`. The fake command records its arguments, `CARGO_BUILD_JOBS`, `RUST_TEST_THREADS`, `RUSTFLAGS`, `CARGO_TARGET_DIR`, the effective file-creation mode, and target-directory mode. Assert exact values and assert that an existing symlink target is rejected.

- [ ] **Step 2: Run the self-test to verify RED**

Run: `bash scripts/test-workspace-self-test.sh`

Expected: FAIL because `scripts/test-workspace.sh` does not exist.

- [ ] **Step 3: Implement the minimal runner**

Implement `scripts/test-workspace.sh` with `set -euo pipefail`, repository-root discovery, umask and environment setup, target symlink rejection, `install -d -m 700`, canonical target export, and `cargo test --workspace --all-features`.

- [ ] **Step 4: Run the self-test to verify GREEN**

Run: `bash scripts/test-workspace-self-test.sh`

Expected: `test-workspace self-test: ok`.

- [ ] **Step 5: Document the canonical command**

Replace the raw Rust workspace `cargo test` command in the README acceptance gate with `bash scripts/test-workspace.sh`, and add the runner self-test next to the other shell self-tests.

- [ ] **Step 6: Verify the real suite**

Run: `HERDR_A2A_TEST_TARGET_DIR="$HOME/.local/state/herdr-test-target/canonical" bash scripts/test-workspace.sh`

Expected: all workspace tests pass with all features.

Run: `git diff --check && bash -n scripts/test-workspace.sh scripts/test-workspace-self-test.sh`

Expected: zero exit and no output.

### Task 2: Full-suite baseline defects

**Files:**
- Modify: `crates/herdr-a2a-cli/tests/managed_install.rs`
- Modify: `crates/herdr-a2a-cli/src/coordinator.rs`

**Interfaces:**
- Consumes: the existing managed-process shared retirement deadline and exact coordinator lock record.
- Produces: `wait_for_unheld_starting_coordinator_lock(&RuntimePaths, &ManagedStartingProcessEntry, Instant)` and Linux test-only zombie-aware liveness checks.

- [ ] **Step 1: Verify the three focused RED cases**

Run the exact persisted-path, coordinator-reservation retirement, and forced aggregate-timeout tests with the canonical runner environment. Expected: each fails for its independently diagnosed reason.

- [ ] **Step 2: Correct the persisted-path fixture**

Use `HOME` on macOS and `XDG_DATA_HOME` elsewhere for both the newline and non-UTF-8 cases. Run the exact test and expect PASS.

- [ ] **Step 3: Add bounded coordinator-lock release waiting**

Replace the one-shot post-process lock check with an async retry bounded by the existing shared stop deadline. Return the existing fail-closed error if the lock remains held, and perform the same exact record validation after acquiring it. Run the coordinator-reservation and stale-reservation exact tests and expect PASS.

- [ ] **Step 4: Make Linux fixture liveness zombie-aware**

Read `/proc/<pid>/stat` in the test helper and treat state `Z` as retired. For process groups, scan numeric `/proc` entries and count only non-zombie members whose pgrp matches the exact group. Preserve `kill -0` behavior on non-Linux platforms. Run the forced aggregate-timeout test and expect PASS.

- [ ] **Step 5: Align the confirmed restart-timeout contract**

Verify the exact Rust session-protocol test fails because it expects `broker_unavailable` while the implementation and Pi integration fixture use `deadline_expired` for a confirmed, reachable task. Change only the stale assertion and run the exact test plus the full session-protocol binary; expect PASS.

- [ ] **Step 6: Verify all focused regressions**

Run all starting-process managed-install tests serially plus the persisted-path test. Expected: all pass.

- [ ] **Step 7: Verify the complete canonical suite and static checks**

Run `HERDR_A2A_TEST_TARGET_DIR="$HOME/.local/state/herdr-test-target/canonical" bash scripts/test-workspace.sh`, the runner self-test, Bash syntax checks, formatting, and `git diff --check`. Expected: zero failures.

- [ ] **Step 8: Commit**

```bash
git add -f docs/superpowers/specs/2026-08-28-test-harness-preconditions.md docs/superpowers/plans/2026-08-28-test-harness-preconditions.md
git add README.md scripts/test-workspace.sh scripts/test-workspace-self-test.sh crates/herdr-a2a-cli/src/coordinator.rs crates/herdr-a2a-cli/tests/managed_install.rs crates/herdr-a2a-cli/tests/session_protocol.rs
git commit -m "test: make workspace verification reproducible"
```
