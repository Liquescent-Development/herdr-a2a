# Purge Reinstall Plugin-State Root Design

## Problem

A managed purge intentionally retains an authenticated `Removed` ownership tombstone while deleting the owned Herdr plugin-state root. A later GitHub reinstall can authenticate that tombstone and accept Herdr's new transactional plugin checkout, but `build_record` then calls `validate_private_directory` on the deleted recorded plugin-state root. The install fails after publishing generation and plugin assets and leaves an install transaction whose rollback cannot complete once Herdr deletes the temporary checkout.

## Required behavior

After transaction recovery, locking, and complete `Removed`-record validation, but before creating a new install transaction, a managed reinstall with purge authority must:

1. Read `HERDR_PLUGIN_STATE_DIR` as an absolute normalized path without creating it.
2. Require exact equality with the authenticated record's `plugin_state_root`.
3. Recreate or harden only that exact path through the existing `prepare_managed_plugin_state_root` namespace walk.
4. Continue using existing private ownership, no-symlink, directory-mode, and Herdr namespace checks.

Records that are active, partially removed, linked-development, lack purge authority, are malformed, or name a different configured state root must retain their existing fail-closed behavior. No unrelated state path may be created or adopted.

## Verification

Automated coverage must reproduce a purge that removes both plugin state and the old checkout, then reinstall from a distinct Herdr transactional checkout. It must also prove that changing `HERDR_PLUGIN_STATE_DIR` after a non-purge removal is rejected without mutating ownership, Pi settings, or either state root.

The release gate remains the canonical Rust workspace suite, Pi tests and typecheck, formatting, Clippy with only documented pre-existing lints, shell/package/signing checks, and the real purge uninstall → GitHub install → fresh authorized Pi pane workflow.
