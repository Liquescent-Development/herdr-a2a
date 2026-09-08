#!/usr/bin/env bash
# Only this test invocation inherits TMPDIR; never change Pi/A2A runtime settings.
set -euo pipefail
fail() { printf 'test-scratch: %s\n' "$*" >&2; exit 1; }
[[ $# -gt 0 ]] || fail 'test command required'
parent=${HERDR_A2A_TEST_SCRATCH_ROOT:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/herdr-a2a/test-scratch}
[[ ! -L $parent ]] || fail 'scratch root must not be a symlink'
mkdir -p -- "$parent"
[[ -O $parent ]] || fail 'scratch root must be owned by this user'
chmod 700 -- "$parent"
parent=$(CDPATH= cd -- "$parent" && pwd -P)
if [[ $(uname -s) == Linux ]]; then
    filesystem=$(findmnt -n -o FSTYPE -T "$parent")
    [[ -n $filesystem && $filesystem != tmpfs && $filesystem != ramfs ]] || fail 'scratch root must be disk-backed'
fi
run_root=$(mktemp -d "$parent/run.XXXXXXXX")
# Exclusive mktemp output only. No search/delete of older roots or descriptors.
trap 'rm -rf -- "$run_root"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR=$run_root
export HERDR_A2A_TEST_SCRATCH_ROOT=$run_root
"$@"
