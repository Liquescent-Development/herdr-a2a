#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf '%s\n' "test-workspace: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
target_dir=${HERDR_A2A_TEST_TARGET_DIR:-${HOME:?HOME is required}/.herdr-a2a-test-target}

[[ ! -L $target_dir ]] || fail "target directory must not be a symlink: $target_dir"
install -d -m 700 -- "$target_dir"
chmod 700 -- "$target_dir"
target_dir=$(CDPATH= cd -- "$target_dir" && pwd -P)

umask 0022
export CARGO_BUILD_JOBS=2
export RUST_TEST_THREADS=1
export RUSTFLAGS='-C debuginfo=0'
unset CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_DIR=$target_dir

cd "$repository_root"
exec cargo test --workspace --all-features
