# Purge Reinstall Plugin-State Root Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an authenticated managed reinstall recreate the exact plugin-state root deleted by purge before any new install transaction is written.

**Architecture:** Split parsing of `HERDR_PLUGIN_STATE_DIR` from namespace materialization. During `install_inner`, after complete `Removed` validation, compare the configured path to the recorded path and then invoke the existing fail-closed managed namespace walker.

**Tech Stack:** Rust 2024, rustix filesystem APIs, Cargo integration tests, Bash release gates

**Spec:** `docs/superpowers/specs/2026-08-30-purge-reinstall-state-root.md`

## Global Constraints

- Preserve strict ownership, path, symlink, mode, hashing, and namespace validation.
- Validate a `Removed` record against its recorded root before recreating state.
- Never create or adopt a configured state root that differs from the authenticated record.
- Active, partially removed, and linked-development installations remain fail closed.

---

### Task 1: Reproduce purge reinstall and configured-root substitution

**Files:**
- Modify: `crates/herdr-a2a-cli/tests/managed_install.rs`

**Interfaces:**
- Consumes: `ManagedFixture::{remove_after_exact_plugin_absence, transactional_plugin_root, install_from_plugin_root}`
- Produces: integration regressions for exact state-root recreation and mismatch rejection

- [x] **Step 1: Write the failing purge-reinstall test**

Add `reinstall_from_new_transaction_root_recreates_purged_plugin_state`, which installs, prepares a distinct checkout, purges, removes the old checkout, proves the state root is absent, reinstalls, and asserts `Ready`, exact new plugin root, private recreated state root, and no transaction journal.

- [x] **Step 2: Run the purge test to verify it fails**

Run: `cargo test -p herdr-a2a-cli --features test-harness --test managed_install reinstall_from_new_transaction_root_recreates_purged_plugin_state -- --exact`

Expected: FAIL because `build_record` cannot open the deleted recorded plugin-state root.

- [x] **Step 3: Write the failing substitution test**

Add `removed_reinstall_rejects_a_changed_plugin_state_root_without_mutation`, which non-purge removes, configures another syntactically valid Herdr state namespace, attempts reinstall, and asserts `ownership_conflict`, byte-identical ownership/Pi settings, no alternate root, and unchanged retained state.

- [x] **Step 4: Run the substitution test to verify it fails**

Run the exact new test through Cargo.

Expected: FAIL because current code ignores the changed environment path and completes reinstall.

### Task 2: Prepare only the authenticated removed state root

**Files:**
- Modify: `crates/herdr-a2a-cli/src/managed.rs`
- Test: `crates/herdr-a2a-cli/tests/managed_install.rs`

**Interfaces:**
- Produces: `required_plugin_state_root_path() -> ManagedResult<PathBuf>` and `prepare_removed_plugin_state_root_for_reinstall(&OwnershipRecord, &str) -> ManagedResult<()>`

- [x] **Step 1: Split environment path parsing from preparation**

Make `required_plugin_state_root` call a side-effect-free `required_plugin_state_root_path`, then retain its existing managed/linked preparation behavior.

- [x] **Step 2: Add the narrow removed-record preflight**

For `Removed`, managed, purge-authoritative records only, require exact equality between the configured and recorded state roots, then call `prepare_managed_plugin_state_root` after `validate_removed_record_for_reinstall` succeeds and before transaction creation.

- [x] **Step 3: Run both focused regressions**

Expected: PASS with no journal residue and no unrelated state mutation.

- [x] **Step 4: Run all managed-install tests**

Expected: all 133 tests pass under the canonical test environment.

- [x] **Step 5: Commit the fix and its design records**

Commit message: `fix: recreate purged plugin state on reinstall`

### Task 3: Release and consumer verification

**Files:**
- Modify version metadata in Cargo manifests/lockfile, Pi package files, plugin manifest, README, and release self-test expectations.

**Interfaces:**
- Produces: trusted signed `v0.1.10` release and verified installation

- [x] **Step 1: Update synchronized versions to 0.1.10 and commit separately**
- [ ] **Step 2: Run canonical Rust, Pi, format, Clippy, shell, packaging, signing, smoke, and npm-pack gates**
- [ ] **Step 3: Request code review, merge the reviewed branch, and sign/push `v0.1.10` at the merge commit**
- [ ] **Step 4: Verify all published assets and Linux checksums/version**
- [ ] **Step 5: Recover the current authenticated failed install, purge, install from GitHub, and start one authorized temporary Pi pane**
- [ ] **Step 6: Verify ownership relocation, descriptor publication, Doctor, broker, and A2A operation, then remove the temporary pane**
