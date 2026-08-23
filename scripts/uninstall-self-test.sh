#!/usr/bin/env bash
set -euo pipefail
umask 077

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
uninstall=$repository_root/plugins/herdr/scripts/uninstall.sh
fixture=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-uninstall-test.XXXXXX")
fixture=$(CDPATH= cd -- "$fixture" && pwd -P)
cleanup() {
    find "$fixture" -depth -type l -delete
    find "$fixture" -depth -type f -delete
    find "$fixture" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

hostile_log=$fixture/hostile-runtime.log
helper_log=$fixture/helper.log
loader_log=$fixture/hostile-loader.log
bash_env=$fixture/hostile-bash-env
cat > "$bash_env" <<'SH'
printf '%s\n' injected-bash-env >> "$HOSTILE_LOG"
SH
helper=$fixture/herdr-a2a-rescue
cat > "$helper" <<'SH'
#!/bin/sh
printf '%s\n' executed-helper >> "$HELPER_LOG"
exit 97
SH
chmod 700 "$helper"

loader=$fixture/hostile-loader
if [ "$(uname -s)" = Linux ] && command -v cc >/dev/null 2>&1; then
    cat > "$fixture/hostile-loader.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void herdr_a2a_loader_probe(void) {
    const char *path = getenv("HOSTILE_LOADER_LOG");
    if (path != NULL) {
        FILE *file = fopen(path, "a");
        if (file != NULL) {
            fputs("injected-loader\n", file);
            fclose(file);
        }
    }
}
C
    cc -shared -fPIC -o "$loader" "$fixture/hostile-loader.c"
fi

[ ! -x "$uninstall" ] || {
    printf '%s\n' "uninstall self-test: recovery notice is executable" >&2
    exit 1
}

set +e
LD_PRELOAD=$loader HOSTILE_LOADER_LOG=$loader_log \
    HOME=$fixture/'redirected home' XDG_DATA_HOME=$fixture/'redirected data' \
    "$uninstall" --skip-herdr-unregister \
    > "$fixture/direct-stdout" 2> "$fixture/direct-stderr"
direct_status=$?
set -e

[ "$direct_status" -ne 0 ]
[ ! -e "$loader_log" ] || {
    printf '%s\n' "uninstall self-test: loader ran before direct-exec rejection" >&2
    exit 1
}

set +e
/bin/bash -p -c \
    'export BASH_ENV=$2 ENV=$2 LD_PRELOAD=$3 HOSTILE_LOG=$4 HELPER_LOG=$5; . "$1" --skip-herdr-unregister; status=$?; [ "$BASH_ENV" = "$2" ] && [ "$ENV" = "$2" ] && [ "$LD_PRELOAD" = "$3" ] && [ "$HOSTILE_LOG" = "$4" ] && [ "$HELPER_LOG" = "$5" ] || exit 98; exit "$status"' \
    herdr-a2a-rescue-source "$uninstall" "$bash_env" "$loader" "$hostile_log" "$helper_log" \
    > "$fixture/stdout" 2> "$fixture/stderr"
status=$?
set -e

[ "$status" -eq 1 ] || {
    printf '%s\n' "uninstall self-test: source notice mutated its caller environment" >&2
    exit 1
}
grep -q rescue_unavailable "$fixture/stderr"
! grep -Fq "$fixture" "$fixture/stderr"
[ ! -e "$hostile_log" ] || {
    printf '%s\n' "uninstall self-test: shell startup injection executed" >&2
    exit 1
}
[ ! -e "$helper_log" ] || {
    printf '%s\n' "uninstall self-test: unproved helper executed" >&2
    exit 1
}
[ ! -s "$fixture/stdout" ]

printf '%s\n' "uninstall self-test: ok"
