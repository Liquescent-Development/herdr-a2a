#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf '%s\n' "managed install self-test: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
binary=$repository_root/target/debug/herdr-a2a
[ -x "$binary" ] || fail "build the debug herdr-a2a binary before this self-test"

temporary=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-self-test.XXXXXX")
temporary=$(CDPATH= cd -- "$temporary" && pwd -P)
cleanup() {
    rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$temporary"

plugin=$temporary/config\ with\ spaces/herdr/plugins/.tmp-install-987-654/checkout/plugins/herdr
bundle=$temporary/bundle\ with\ spaces
home=$temporary/home\ with\ spaces
plugin_state=$temporary/plugin-state-base/herdr/plugins/herdr.a2a
fake_bin=$temporary/fake-bin
mkdir -p "$plugin/scripts" "$bundle/bin" "$bundle/pi/extensions" \
    "$bundle/pi/src" "$bundle/pi/skills/herdr-a2a" "$home" "$plugin_state" "$fake_bin"
chmod 700 "$plugin" "$plugin_state"
cp "$repository_root/plugins/herdr/scripts/install.sh" "$plugin/scripts/install.sh"
cp "$repository_root/plugins/herdr/scripts/uninstall.sh" "$plugin/scripts/uninstall.sh"
cp "$repository_root/plugins/herdr/herdr-plugin.toml" "$plugin/herdr-plugin.toml"
cp "$binary" "$bundle/bin/herdr-a2a"
chmod 700 "$bundle/bin/herdr-a2a"
cp "$repository_root/integrations/pi/package.json" "$bundle/pi/package.json"
cp "$repository_root/integrations/pi/extensions/herdr-a2a.ts" \
    "$bundle/pi/extensions/herdr-a2a.ts"
cp "$repository_root/integrations/pi/src/inbox-pump.ts" \
    "$bundle/pi/src/inbox-pump.ts"
cp "$repository_root/integrations/pi/src/session-client.ts" \
    "$bundle/pi/src/session-client.ts"
cp "$repository_root/integrations/pi/src/team-command.ts" \
    "$bundle/pi/src/team-command.ts"
cp "$repository_root/integrations/pi/skills/herdr-a2a/SKILL.md" \
    "$bundle/pi/skills/herdr-a2a/SKILL.md"

plugin_link=$temporary/plugin-link
ln -s "$plugin" "$plugin_link"
if HOME=$home PATH=/usr/bin:/bin HERDR_A2A_INSTALL_BUNDLE=$bundle \
    bash "$plugin_link/scripts/install.sh" >/dev/null 2>&1; then
    fail "final plugin-root symlink was hidden by the shell bootstrap"
fi
[ ! -e "$plugin/libexec" ] && [ ! -e "$plugin/stable-bin-path" ] || \
    fail "plugin assets changed before final-symlink validation failed"
for debris in "$plugin"/.bootstrap-* "$plugin"/.managed-stage-*; do
    [ ! -e "$debris" ] || fail "plugin debris was created before validation"
done

real_parent=$temporary/real-parent
mkdir "$real_parent"
cp -R "$plugin" "$real_parent/plugin"
intermediate_link=$temporary/intermediate-link
ln -s "$real_parent" "$intermediate_link"
if HOME=$home PATH=/usr/bin:/bin HERDR_A2A_INSTALL_BUNDLE=$bundle \
    bash "$intermediate_link/plugin/scripts/install.sh" >/dev/null 2>&1; then
    fail "intermediate plugin-root symlink was hidden by the shell bootstrap"
fi
[ ! -e "$real_parent/plugin/libexec" ] && [ ! -e "$real_parent/plugin/stable-bin-path" ] || \
    fail "plugin assets changed before intermediate-symlink validation failed"

for forbidden in cargo node npm; do
    printf '%s\n' '#!/bin/sh' "touch '$temporary/forbidden-$forbidden'" 'exit 99' \
        > "$fake_bin/$forbidden"
    chmod 700 "$fake_bin/$forbidden"
done

managed_checkout_base=$temporary/managed-checkout
managed_checkout_plugin=$managed_checkout_base/config/herdr/plugins/.tmp-install-123-456/checkout/plugins/herdr
managed_checkout_home=$temporary/managed-checkout-home
managed_checkout_state_base=$temporary/managed-checkout-state-base
managed_checkout_state=$managed_checkout_state_base/herdr/plugins/herdr.a2a
managed_checkout_bin=$temporary/managed-checkout-bin
managed_checkout_python=$(command -v python3) || fail "python3 is required for the clean-install fixture"
mkdir -p "$managed_checkout_plugin/scripts" "$managed_checkout_home/.pi/agent" \
    "$managed_checkout_state_base" "$managed_checkout_bin"
cp "$repository_root/plugins/herdr/scripts/install.sh" \
    "$managed_checkout_plugin/scripts/install.sh"
cp "$repository_root/plugins/herdr/scripts/uninstall.sh" \
    "$managed_checkout_plugin/scripts/uninstall.sh"
cp "$repository_root/plugins/herdr/herdr-plugin.toml" \
    "$managed_checkout_plugin/herdr-plugin.toml"
chmod 664 "$managed_checkout_plugin/herdr-plugin.toml"
chmod 775 "$managed_checkout_plugin/scripts"
chmod 664 "$managed_checkout_plugin/scripts/uninstall.sh"
printf '%s\n' '{"packages": []}' > "$managed_checkout_home/.pi/agent/settings.json"
cat > "$managed_checkout_bin/pi" <<'SH'
#!/bin/sh
set -eu
case "${1:-}" in
    --version) printf '%s\n' 0.84.2 ;;
    install)
        "$HERDR_A2A_TEST_PYTHON" - "$HOME/.pi/agent/settings.json" "$2" <<'PY'
import json, os, sys, tempfile
path, source = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle)
value.setdefault("packages", []).append(source)
fd, temporary = tempfile.mkstemp(prefix=".settings-", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(value, handle)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary, path)
PY
        ;;
    list) ;;
    *) exit 64 ;;
esac
SH
chmod 700 "$managed_checkout_bin/pi"
for directory in \
    "$managed_checkout_base/config/herdr" \
    "$managed_checkout_base/config/herdr/plugins" \
    "$managed_checkout_base/config/herdr/plugins/.tmp-install-123-456" \
    "$managed_checkout_base/config/herdr/plugins/.tmp-install-123-456/checkout" \
    "$managed_checkout_base/config/herdr/plugins/.tmp-install-123-456/checkout/plugins" \
    "$managed_checkout_plugin"
do
    chmod 775 "$directory"
done
chmod 775 "$managed_checkout_home/.pi" "$managed_checkout_home/.pi/agent"
chmod 664 "$managed_checkout_home/.pi/agent/settings.json"
chmod 755 "$managed_checkout_state_base"
(
    umask 002
    HOME=$managed_checkout_home PATH=$managed_checkout_bin:/usr/bin:/bin \
    HERDR_A2A_TEST_PYTHON=$managed_checkout_python \
    HERDR_A2A_INSTALL_BUNDLE=$bundle HERDR_PLUGIN_STATE_DIR=$managed_checkout_state \
        bash "$managed_checkout_plugin/scripts/install.sh" >/dev/null
)
[ "$(find "$managed_checkout_base/config/herdr" -type d -perm -0020 | wc -l | tr -d ' ')" = 0 ] || \
    fail "managed checkout retained group-writable directories"
[ "$(find "$managed_checkout_plugin" -maxdepth 0 -type d -perm 0700 -print)" = \
    "$managed_checkout_plugin" ] || fail "managed plugin root was not hardened to 0700"
for private_directory in \
    "$managed_checkout_home/.pi" \
    "$managed_checkout_home/.pi/agent" \
    "$managed_checkout_state_base/herdr" \
    "$managed_checkout_state_base/herdr/plugins" \
    "$managed_checkout_state"
do
    [ "$(find "$private_directory" -maxdepth 0 -type d -perm 0700 -print)" = \
        "$private_directory" ] || fail "clean-install directory is not private: $private_directory"
done
[ "$(find "$managed_checkout_home/.pi/agent/settings.json" -type f -perm 0600 -print)" = \
    "$managed_checkout_home/.pi/agent/settings.json" ] || \
    fail "clean-install Pi settings are not private"
[ "$(find "$managed_checkout_state_base" -maxdepth 0 -type d -perm 0755 -print)" = \
    "$managed_checkout_state_base" ] || fail "managed install changed the state base"

dev_repository=$temporary/dev-repository
dev_plugin=$dev_repository/plugins/herdr
dev_home=$temporary/dev-home
dev_plugin_state=$temporary/dev-plugin-state
dev_fake_bin=$temporary/dev-fake-bin
mkdir -p "$dev_plugin/scripts" "$dev_repository/integrations/pi/extensions" \
    "$dev_repository/integrations/pi/src" \
    "$dev_repository/integrations/pi/skills/herdr-a2a" \
    "$dev_repository/target/release" "$dev_home" "$dev_plugin_state" "$dev_fake_bin"
chmod 700 "$dev_plugin" "$dev_plugin_state"
cp "$repository_root/plugins/herdr/scripts/install.sh" "$dev_plugin/scripts/install.sh"
cp "$repository_root/plugins/herdr/scripts/uninstall.sh" "$dev_plugin/scripts/uninstall.sh"
cp "$repository_root/plugins/herdr/herdr-plugin.toml" "$dev_plugin/herdr-plugin.toml"
cp "$repository_root/integrations/pi/package.json" "$dev_repository/integrations/pi/package.json"
cp "$repository_root/integrations/pi/extensions/herdr-a2a.ts" \
    "$dev_repository/integrations/pi/extensions/herdr-a2a.ts"
cp "$repository_root/integrations/pi/src/inbox-pump.ts" \
    "$dev_repository/integrations/pi/src/inbox-pump.ts"
cp "$repository_root/integrations/pi/src/session-client.ts" \
    "$dev_repository/integrations/pi/src/session-client.ts"
cp "$repository_root/integrations/pi/src/team-command.ts" \
    "$dev_repository/integrations/pi/src/team-command.ts"
cp "$repository_root/integrations/pi/skills/herdr-a2a/SKILL.md" \
    "$dev_repository/integrations/pi/skills/herdr-a2a/SKILL.md"
printf '%s\n' '#!/bin/sh' \
    'cp "$HERDR_A2A_TEST_BINARY" "$HERDR_A2A_TEST_REPOSITORY/target/release/herdr-a2a"' \
    'strip "$HERDR_A2A_TEST_REPOSITORY/target/release/herdr-a2a"' \
    'chmod 700 "$HERDR_A2A_TEST_REPOSITORY/target/release/herdr-a2a"' \
    > "$dev_fake_bin/cargo"
chmod 700 "$dev_fake_bin/cargo"
printf '%s\n' '#!/bin/sh' \
    'touch "$HERDR_A2A_TEST_UNTRUSTED_VALIDATOR_MARKER"' \
    'exit 99' > "$dev_fake_bin/herdr-a2a"
chmod 700 "$dev_fake_bin/herdr-a2a"
HOME=$dev_home PATH=$dev_fake_bin:/usr/bin:/bin \
HERDR_A2A_TEST_BINARY=$binary HERDR_A2A_TEST_REPOSITORY=$dev_repository \
HERDR_A2A_TEST_UNTRUSTED_VALIDATOR_MARKER=$temporary/untrusted-validator-ran \
HERDR_PLUGIN_STATE_DIR=$dev_plugin_state \
    bash "$dev_plugin/scripts/install.sh" --dev >/dev/null
[ ! -e "$temporary/untrusted-validator-ran" ] || \
    fail "development install executed an arbitrary PATH validator"
case $(uname -s) in
    Darwin) dev_stable_root=$dev_home/Library/Application\ Support/herdr-a2a ;;
    Linux) dev_stable_root=$dev_home/.local/share/herdr-a2a ;;
esac
grep -q '"install_kind": "linked-dev"' "$dev_stable_root/ownership.json" || \
    fail "development branch did not record linked-dev"
set -- "$dev_stable_root"/generations/*
[ "$#" -eq 1 ] && [ -f "$1/pi/src/inbox-pump.ts" ] && \
    [ -n "$(find "$1/pi/src/inbox-pump.ts" -type f -perm 0600 -print)" ] && \
    [ -f "$1/pi/src/session-client.ts" ] && \
    [ -f "$1/pi/src/team-command.ts" ] || \
    fail "development install omitted or mis-moded Pi source modules imported by the extension"

if HOME=$home PATH=$fake_bin:/usr/bin:/bin HERDR_A2A_INSTALL_BUNDLE=relative \
    bash "$plugin/scripts/install.sh" >/dev/null 2>&1; then
    fail "relative HERDR_A2A_INSTALL_BUNDLE was accepted"
fi

HOME=$home PATH=$fake_bin:/usr/bin:/bin HERDR_A2A_INSTALL_BUNDLE=$bundle \
HERDR_PLUGIN_STATE_DIR=$plugin_state \
    bash "$plugin/scripts/install.sh" >/dev/null

production_plugin=$temporary/production-config/herdr/plugins/.tmp-install-246-802/checkout/plugins/herdr
production_home=$temporary/production-home
production_state_home=$temporary/production-state-home
production_bin=$temporary/production-bin
production_output=$temporary/production-output
production_binary=$dev_repository/target/release/herdr-a2a
[ -x "$production_binary" ] || fail "development fixture did not produce a release binary"
mkdir -p "$production_plugin/scripts" "$production_home" "$production_state_home" \
    "$production_state_home/herdr/plugins/herdr.a2a" "$production_bin" \
    "$production_output"
chmod 700 "$production_plugin" "$production_state_home" \
    "$production_state_home/herdr/plugins/herdr.a2a"
cp "$repository_root/plugins/herdr/scripts/install.sh" "$production_plugin/scripts/install.sh"
cp "$repository_root/plugins/herdr/scripts/uninstall.sh" "$production_plugin/scripts/uninstall.sh"
cp "$repository_root/plugins/herdr/herdr-plugin.toml" "$production_plugin/herdr-plugin.toml"
case "$(uname -s):$(uname -m)" in
    Darwin:arm64) production_target=aarch64-apple-darwin; production_suffix=macos-arm64 ;;
    Darwin:x86_64) production_target=x86_64-apple-darwin; production_suffix=macos-x86_64 ;;
    Linux:aarch64) production_target=aarch64-unknown-linux-gnu; production_suffix=linux-arm64 ;;
    Linux:x86_64) production_target=x86_64-unknown-linux-gnu; production_suffix=linux-x86_64 ;;
    *) fail "unsupported production self-test platform" ;;
esac
bash "$repository_root/scripts/package-release.sh" --target "$production_target" \
    --binary "$production_binary" --output-dir "$production_output"
production_stem=$production_output/herdr-a2a-0.1.9-$production_suffix
production_asset=$production_stem.tar.gz
production_asset_sha=$production_asset.sha256
production_bootstrap_sha=$production_stem.sha256
printf '%s\n' '#!/bin/sh' 'set -eu' \
    'url=' \
    'destination=' \
    'while [ "$#" -gt 0 ]; do' \
    '  case "$1" in' \
    '    -o) destination=$2; shift 2 ;;' \
    '    -*) shift ;;' \
    '    *) url=$1; shift ;;' \
    '  esac' \
    'done' \
    'case "$url" in' \
    '  *.tar.gz.sha256) source=$HERDR_A2A_TEST_RELEASE_ASSET_SHA ;;' \
    '  *.tar.gz) source=$HERDR_A2A_TEST_RELEASE_ASSET ;;' \
    '  *.sha256) source=$HERDR_A2A_TEST_RELEASE_BOOTSTRAP_SHA ;;' \
    '  *) source=$HERDR_A2A_TEST_RELEASE_BOOTSTRAP ;;' \
    'esac' \
    'cp "$source" "$destination"' > "$production_bin/curl"
chmod 700 "$production_bin/curl"
HOME=$production_home XDG_STATE_HOME=$production_state_home TMPDIR=$temporary \
PATH=$production_bin:/usr/bin:/bin \
HERDR_A2A_TEST_RELEASE_ASSET=$production_asset \
HERDR_A2A_TEST_RELEASE_ASSET_SHA=$production_asset_sha \
HERDR_A2A_TEST_RELEASE_BOOTSTRAP=$production_stem \
HERDR_A2A_TEST_RELEASE_BOOTSTRAP_SHA=$production_bootstrap_sha \
    bash "$production_plugin/scripts/install.sh" >/dev/null
case $(uname -s) in
    Darwin) production_stable_root=$production_home/Library/Application\ Support/herdr-a2a ;;
    Linux) production_stable_root=$production_home/.local/share/herdr-a2a ;;
esac
[ -f "$production_stable_root/ownership.json" ] || \
    fail "fresh production install without a PATH validator did not complete"
set -- "$production_stable_root"/generations/*
[ "$#" -eq 1 ] && [ -f "$1/pi/src/inbox-pump.ts" ] && \
    [ -n "$(find "$1/pi/src/inbox-pump.ts" -type f -perm 0600 -print)" ] || \
    fail "production install omitted or mis-moded the inbox pump"
grep -q "$production_state_home/herdr/plugins/herdr.a2a" \
    "$production_stable_root/ownership.json" || \
    fail "ordinary production install did not derive the managed plugin state directory"

case $(uname -s) in
    Darwin) stable_root=$home/Library/Application\ Support/herdr-a2a ;;
    Linux) stable_root=$home/.local/share/herdr-a2a ;;
    *) fail "unsupported self-test platform" ;;
esac

[ -f "$stable_root/ownership.json" ] || fail "ownership record was not installed"
[ -x "$plugin/libexec/herdr-a2a-dispatch" ] || fail "native helper was not installed"
[ -f "$plugin/stable-bin-path" ] || fail "stable pointer was not installed"
[ "$(wc -l < "$plugin/stable-bin-path" | tr -d ' ')" = 1 ] || \
    fail "stable pointer is not exactly one line"
pointed_binary=$(sed -n '1p' "$plugin/stable-bin-path")
[ -x "$pointed_binary" ] || fail "stable pointer does not name an executable"
grep -q '"state": "PiAdapterPending"' "$stable_root/ownership.json" || \
    fail "Pi-absent installation did not commit pending state"
grep -q '"install_kind": "managed"' "$stable_root/ownership.json" || \
    fail "managed installation kind was not recorded"

mkdir "$stable_root/generations/.stage-interrupted"
chmod 700 "$stable_root/generations/.stage-interrupted"
if HOME=$home PATH=$fake_bin:/usr/bin:/bin HERDR_A2A_INSTALL_BUNDLE=$bundle \
    HERDR_PLUGIN_STATE_DIR=$plugin_state \
    bash "$plugin/scripts/install.sh" >/dev/null 2>&1; then
    fail "unauthenticated generation stage was recursively deleted"
fi
[ -d "$stable_root/generations/.stage-interrupted" ] || \
    fail "unauthenticated generation stage was not preserved"

for forbidden in cargo node npm; do
    [ ! -e "$temporary/forbidden-$forbidden" ] || \
        fail "$forbidden ran in the managed installation path"
done

printf '%s\n' "managed install self-test: ok"
