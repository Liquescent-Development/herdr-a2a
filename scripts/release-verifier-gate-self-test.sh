#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "release-verifier-gate self-test: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-release-verifier-gate.XXXXXX")
cleanup() {
    rm -rf -- "$fixture"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$fixture/bin"
marker=$fixture/verifier-invoked
cat > "$fixture/bin/bash" <<'SH'
#!/bin/sh
if [ "${1:-}" = "$HERDR_A2A_EXPECTED_VERIFIER_SELF_TEST" ]; then
    : > "$HERDR_A2A_VERIFIER_MARKER"
fi
exec /bin/bash "$@"
SH
chmod 700 "$fixture/bin/bash"

PATH="$fixture/bin:$PATH" \
HERDR_A2A_EXPECTED_VERIFIER_SELF_TEST="$repository_root/scripts/verify-release-tag-self-test.sh" \
HERDR_A2A_VERIFIER_MARKER="$marker" \
"$repository_root/scripts/package-release.sh" --self-test

[[ -f "$marker" ]] || fail 'package release self-test did not run the signed-tag verifier self-test'
printf '%s\n' 'release-verifier-gate self-test: ok'
