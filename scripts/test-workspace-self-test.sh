#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf '%s\n' "test-workspace self-test: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
runner=$repository_root/scripts/test-workspace.sh
[[ -f $runner ]] || fail "runner is missing"

parent=${HERDR_A2A_TEST_SCRATCH_ROOT:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/herdr-a2a/test-scratch}
mkdir -p -- "$parent"
test_root=$(mktemp -d "$parent/self-test.XXXXXXXX")
trap 'rm -rf -- "$test_root"' EXIT
python_command=${PYTHON:-$(command -v python3)}
[[ $python_command == /* ]] || fail 'PYTHON must be absolute'
mkdir -p "$test_root/repository/scripts" "$test_root/bin" "$test_root/capture"
cp "$runner" "$test_root/repository/scripts/test-workspace.sh"
cp "$repository_root/scripts/with-test-scratch.sh" "$test_root/repository/scripts/with-test-scratch.sh"
chmod 700 "$test_root/repository/scripts/test-workspace.sh"

cat >"$test_root/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
: "${TEST_CAPTURE_DIR:?}"
printf '%s\n' "$@" >"$TEST_CAPTURE_DIR/arguments"
printf '%s\n' "$CARGO_BUILD_JOBS" >"$TEST_CAPTURE_DIR/build-jobs"
printf '%s\n' "$RUST_TEST_THREADS" >"$TEST_CAPTURE_DIR/test-threads"
printf '%s\n' "$RUSTFLAGS" >"$TEST_CAPTURE_DIR/rustflags"
printf '%s\n' "${CARGO_ENCODED_RUSTFLAGS-unset}" >"$TEST_CAPTURE_DIR/encoded-rustflags"
printf '%s\n' "$CARGO_TARGET_DIR" >"$TEST_CAPTURE_DIR/target-dir"
umask >"$TEST_CAPTURE_DIR/umask"
printf created >"$TEST_CAPTURE_DIR/created-file"
printf '%s\n' "$PWD" >"$TEST_CAPTURE_DIR/working-directory"
printf '%s\n' "$TMPDIR" >"$TEST_CAPTURE_DIR/tmpdir"
mkdir -p "$TMPDIR/herdr managed install fixture"
printf owned >"$TMPDIR/herdr managed install fixture/data"
exit "${TEST_EXIT:-0}"
CARGO
chmod 700 "$test_root/bin/cargo"

HOME="$test_root/home" \
PATH="$test_root/bin:$PATH" \
TEST_CAPTURE_DIR="$test_root/capture" \
CARGO_TARGET_DIR="$test_root/attacker-target" \
CARGO_BUILD_JOBS=99 \
RUST_TEST_THREADS=99 \
RUSTFLAGS='--cfg attacker_flag' \
CARGO_ENCODED_RUSTFLAGS=attacker_encoded_flag \
bash "$test_root/repository/scripts/test-workspace.sh"

"$python_command" - "$test_root" <<'PY'
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
capture = root / "capture"
expected = {
    "arguments": "test\n--workspace\n--all-features\n",
    "build-jobs": "2\n",
    "test-threads": "1\n",
    "rustflags": "-C debuginfo=0\n",
    "encoded-rustflags": "unset\n",
    "target-dir": f"{root}/home/.herdr-a2a-test-target\n",
    "umask": "0022\n",
    "working-directory": f"{root}/repository\n",
}
for name, wanted in expected.items():
    actual = (capture / name).read_text()
    if actual != wanted:
        raise SystemExit(f"{name}: expected {wanted!r}, got {actual!r}")

target = root / "home/.herdr-a2a-test-target"
if stat.S_IMODE(target.stat().st_mode) != 0o700:
    raise SystemExit("dedicated target directory is not mode 0700")
if stat.S_IMODE((capture / "created-file").stat().st_mode) != 0o644:
    raise SystemExit("runner did not enforce umask 0022")
PY

rm -rf -- "$test_root/home/.herdr-a2a-test-target"
mkdir -p "$test_root/symlink-destination"
ln -s "$test_root/symlink-destination" "$test_root/home/.herdr-a2a-test-target"
rm -f -- "$test_root/capture/arguments"
if HOME="$test_root/home" PATH="$test_root/bin:$PATH" TEST_CAPTURE_DIR="$test_root/capture" \
    bash "$test_root/repository/scripts/test-workspace.sh" >/dev/null 2>&1; then
    fail "runner accepted a symlink target directory"
fi
[[ ! -e $test_root/capture/arguments ]] || fail "runner invoked cargo after rejecting a symlink"

# Both success and nonzero test exits retire only the newly owned scratch tree.
success_tmp=$(<"$test_root/capture/tmpdir")
[[ ! -e $success_tmp ]] || fail 'successful test left scratch behind'
mkdir -p "$test_root/neighbor"
printf keep >"$test_root/neighbor/descriptor"
set +e
HOME="$test_root/failure-home" PATH="$test_root/bin:$PATH" TEST_CAPTURE_DIR="$test_root/capture" \
TEST_EXIT=7 bash "$test_root/repository/scripts/test-workspace.sh"
code=$?
set -e
[[ $code == 7 ]] || fail 'nonzero cargo status was lost'
failure_tmp=$(<"$test_root/capture/tmpdir")
[[ ! -e $failure_tmp ]] || fail 'failed test left scratch behind'
[[ $(<"$test_root/neighbor/descriptor") == keep ]] || fail 'neighbor descriptor changed'

if [[ $(uname -s) == Linux && $(findmnt -n -o FSTYPE -T /tmp) == tmpfs ]]; then
    # A fresh, owned tiny target only; do not touch historical /tmp build roots.
    ram_target=$(mktemp -d /tmp/herdr-target-rejection.XXXXXXXX)
    set +e
    HOME="$test_root/failure-home" HERDR_A2A_TEST_TARGET_DIR="$ram_target" \
    PATH="$test_root/bin:$PATH" TEST_CAPTURE_DIR="$test_root/capture" \
        bash "$test_root/repository/scripts/test-workspace.sh"
    code=$?
    set -e
    rmdir -- "$ram_target"
    [[ $code != 0 ]] || fail 'tmpfs Cargo target was accepted'
fi
printf '%s\n' 'test-workspace self-test: ok'
