#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "herdr-a2a install: $1" >&2
    exit 1
}

case "$0" in
    /*) script_path=$0 ;;
    *) script_path=$PWD/$0 ;;
esac
case "$script_path" in
    *//*|*/./*|*/../*|*/.|*/..) fail "installer path must be lexically normalized" ;;
esac
script_dir=${script_path%/*}
plugin_root=${script_dir%/*}
repository_root=${plugin_root%/*/*}

temporary=
cleanup() {
    if [ -n "$temporary" ] && [ -d "$temporary" ]; then
        rm -rf -- "$temporary"
    fi
}
trap cleanup EXIT HUP INT TERM

ensure_plugin_state_dir() {
    if [ "${HERDR_PLUGIN_STATE_DIR+x}" = x ]; then
        export HERDR_PLUGIN_STATE_DIR
        return
    fi
    if [ -n "${XDG_STATE_HOME:-}" ]; then
        state_base=$XDG_STATE_HOME
        state_label=XDG_STATE_HOME
    else
        [ -n "${HOME:-}" ] || fail "HOME is required to derive HERDR_PLUGIN_STATE_DIR"
        state_base=$HOME/.local/state
        state_label=HOME
    fi
    case "$state_base" in
        /*) ;;
        *) fail "$state_label must be an absolute normalized path" ;;
    esac
    case "$state_base" in
        /|*//*|*/./*|*/../*|*/.|*/..|*/) \
            fail "$state_label must be an absolute normalized path" ;;
    esac
    HERDR_PLUGIN_STATE_DIR=$state_base/herdr/plugins/herdr.a2a
    [ "${#HERDR_PLUGIN_STATE_DIR}" -le 16384 ] || \
        fail "derived HERDR_PLUGIN_STATE_DIR is too long"
    export HERDR_PLUGIN_STATE_DIR
}

make_development_bundle() {
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-bootstrap-dev.XXXXXX")
    temporary=$(CDPATH= cd -- "$temporary" && pwd -P)
    chmod 700 "$temporary"
    mkdir -p "$temporary/bundle/bin" "$temporary/bundle/pi/extensions" \
        "$temporary/bundle/pi/src" \
        "$temporary/bundle/pi/skills"
    cp "$repository_root/target/release/herdr-a2a" "$temporary/bundle/bin/herdr-a2a"
    chmod 700 "$temporary/bundle/bin/herdr-a2a"
    cp "$repository_root/integrations/pi/package.json" "$temporary/bundle/pi/package.json"
    cp "$repository_root/integrations/pi/extensions/herdr-a2a.ts" \
        "$temporary/bundle/pi/extensions/herdr-a2a.ts"
    cp "$repository_root/integrations/pi/src/inbox-pump.ts" \
        "$temporary/bundle/pi/src/inbox-pump.ts"
    cp "$repository_root/integrations/pi/src/session-client.ts" \
        "$temporary/bundle/pi/src/session-client.ts"
    cp "$repository_root/integrations/pi/src/team-command.ts" \
        "$temporary/bundle/pi/src/team-command.ts"
    cp -R "$repository_root/integrations/pi/skills/herdr-a2a" \
        "$temporary/bundle/pi/skills/herdr-a2a"
    bundle=$temporary/bundle
}

download_release_files() {
    case $(uname -s) in
        Darwin) platform=macos ;;
        Linux) platform=linux ;;
        *) fail "unsupported operating system" ;;
    esac
    case $(uname -m) in
        arm64|aarch64) architecture=arm64 ;;
        x86_64|amd64) architecture=x86_64 ;;
        *) fail "unsupported architecture" ;;
    esac
    version=$(awk -F ' *= *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' \
        "$plugin_root/herdr-plugin.toml")
    [ -n "$version" ] || fail "plugin manifest has no version"
    asset="herdr-a2a-${version}-${platform}-${architecture}.tar.gz"
    base="https://github.com/Liquescent-Development/herdr-a2a/releases/download/v${version}"
    bootstrap="herdr-a2a-${version}-${platform}-${architecture}"
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-bootstrap-release.XXXXXX")
    temporary=$(CDPATH= cd -- "$temporary" && pwd -P)
    chmod 700 "$temporary"
    curl --fail --silent --show-error --location "$base/$asset" -o "$temporary/$asset"
    curl --fail --silent --show-error --location "$base/$asset.sha256" \
        -o "$temporary/$asset.sha256"
    curl --fail --silent --show-error --location "$base/$bootstrap" -o "$temporary/$bootstrap"
    curl --fail --silent --show-error --location "$base/$bootstrap.sha256" \
        -o "$temporary/$bootstrap.sha256"
    verify_sha256 "$temporary/$asset" "$temporary/$asset.sha256"
    verify_sha256 "$temporary/$bootstrap" "$temporary/$bootstrap.sha256"
    chmod 700 "$temporary/$bootstrap"
    validator=$temporary/$bootstrap
    release_archive=$temporary/$asset
}

verify_sha256() {
    verified_file=$1
    checksum_file=$2
    expected=$(awk 'NR == 1 { print $1 }' "$checksum_file")
    case "$expected" in
        *[!0-9a-fA-F]*|'') fail "release digest is not one SHA-256 value" ;;
    esac
    [ "${#expected}" -eq 64 ] || fail "release digest is not 64 hexadecimal characters"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$verified_file" | awk '{ print $1 }')
    else
        actual=$(shasum -a 256 "$verified_file" | awk '{ print $1 }')
    fi
    [ "$actual" = "$expected" ] || fail "release SHA-256 mismatch"
}

if [ "${1:-}" = "--dev" ]; then
    [ "$#" -eq 1 ] || fail "--dev accepts no additional arguments"
    cargo build --release --manifest-path "$repository_root/Cargo.toml" -p herdr-a2a-cli
    validator=$repository_root/target/release/herdr-a2a
    [ -x "$validator" ] || fail "development build did not produce herdr-a2a"
    "$validator" managed validate-plugin-root --path "$plugin_root"
    make_development_bundle
    install_kind=linked-dev
elif [ "$#" -eq 0 ]; then
    install_kind=managed
    if [ -n "${HERDR_A2A_INSTALL_BUNDLE:-}" ]; then
        case "$HERDR_A2A_INSTALL_BUNDLE" in
            /*) bundle=$HERDR_A2A_INSTALL_BUNDLE ;;
            *) fail "HERDR_A2A_INSTALL_BUNDLE must be an absolute test/development path" ;;
        esac
        validator=$bundle/bin/herdr-a2a
        [ -x "$validator" ] || fail "explicit bundle has no native herdr-a2a"
        "$validator" managed validate-plugin-root --path "$plugin_root"
    else
        download_release_files
        "$validator" managed validate-plugin-root --path "$plugin_root"
        "$validator" managed extract-release \
            --archive "$release_archive" --destination "$temporary/bundle"
        bundle=$temporary/bundle
    fi
else
    fail "usage: install.sh [--dev]"
fi

[ -d "$bundle" ] || fail "install bundle is not a directory: $bundle"
ensure_plugin_state_dir
HERDR_A2A_PLUGIN_ROOT=$plugin_root \
HERDR_A2A_INSTALL_KIND=$install_kind \
"$bundle/bin/herdr-a2a" managed install --bundle "$bundle"
HERDR_A2A_PLUGIN_ROOT=$plugin_root \
"$bundle/bin/herdr-a2a" doctor
