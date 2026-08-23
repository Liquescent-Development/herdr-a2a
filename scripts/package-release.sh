#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "package-release: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
self_test_fixture=

cleanup_self_test() {
    if [[ -n "$self_test_fixture" && -d "$self_test_fixture" ]]; then
        rm -rf -- "$self_test_fixture"
    fi
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

write_checksum() {
    local path=$1
    printf '%s  %s\n' "$(sha256_file "$path")" "${path##*/}" > "$path.sha256"
}

verify_checksum() {
    local path=$1 checksum=$2 expected actual recorded
    expected=$(awk 'NR == 1 { print $1 }' "$checksum")
    recorded=$(awk 'NR == 1 { print $2 }' "$checksum")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$recorded" == "${path##*/}" ]] || return 1
    [[ $(awk 'END { print NR }' "$checksum") == 1 ]] || return 1
    actual=$(sha256_file "$path")
    [[ "$actual" == "$expected" ]]
}

manifest_version() {
    awk -F ' *= *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' \
        "$repository_root/plugins/herdr/herdr-plugin.toml"
}

validate_versions() {
    local binary=$1 plugin_version cargo_version pi_version lock_version reported
    plugin_version=$(manifest_version)
    cargo_version=$(awk -F ' *= *' '$1 == "version" { gsub(/"/, "", $2); print $2; exit }' \
        "$repository_root/crates/herdr-a2a-cli/Cargo.toml")
    pi_version=$(node -e \
        'const p=require(process.argv[1]); process.stdout.write(p.version)' \
        "$repository_root/integrations/pi/package.json")
    lock_version=$(node -e \
        'const p=require(process.argv[1]); process.stdout.write(p.packages[""].version)' \
        "$repository_root/integrations/pi/package-lock.json")
    [[ -n "$plugin_version" && "$plugin_version" == "$cargo_version" \
        && "$plugin_version" == "$pi_version" && "$plugin_version" == "$lock_version" ]] || \
        fail "plugin, Cargo, Pi package, and lockfile versions must match"
    [[ -x "$binary" ]] || fail "release binary is not executable"
    reported=$("$binary" --version 2>/dev/null | awk 'NR == 1 { print $NF }') || \
        fail "release binary cannot report its version on this build runner"
    [[ "$reported" == "$plugin_version" ]] || fail "release binary version does not match manifests"
    printf '%s\n' "$plugin_version"
}

target_suffix() {
    case $1 in
        aarch64-apple-darwin) printf '%s\n' macos-arm64 ;;
        x86_64-apple-darwin) printf '%s\n' macos-x86_64 ;;
        aarch64-unknown-linux-gnu) printf '%s\n' linux-arm64 ;;
        x86_64-unknown-linux-gnu) printf '%s\n' linux-x86_64 ;;
        *) fail "unsupported Rust release target: $1" ;;
    esac
}

write_reproducible_archive() {
    local stage=$1 archive=$2
    HERDR_A2A_ARCHIVE_STAGE=$stage HERDR_A2A_ARCHIVE_PATH=$archive node <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const stage = process.env.HERDR_A2A_ARCHIVE_STAGE;
const archive = process.env.HERDR_A2A_ARCHIVE_PATH;
const entries = [
  ["bin/", 0o700, true],
  ["bin/herdr-a2a", 0o700, false],
  ["metadata/", 0o700, true],
  ["metadata/ownership-template.json", 0o600, false],
  ["pi/", 0o700, true],
  ["pi/extensions/", 0o700, true],
  ["pi/extensions/herdr-a2a.ts", 0o600, false],
  ["pi/package.json", 0o600, false],
  ["pi/src/", 0o700, true],
  ["pi/src/inbox-pump.ts", 0o600, false],
  ["pi/src/session-client.ts", 0o600, false],
  ["pi/src/team-command.ts", 0o600, false],
  ["pi/skills/", 0o700, true],
  ["pi/skills/herdr-a2a/", 0o700, true],
  ["pi/skills/herdr-a2a/SKILL.md", 0o600, false],
  ["scripts/", 0o700, true],
  ["scripts/dispatch.sh", 0o700, false],
  ["scripts/uninstall.sh", 0o600, false],
];

function octal(buffer, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, "0") + "\0";
  buffer.write(encoded, offset, length, "ascii");
}

const chunks = [];
for (const [name, mode, directory] of entries) {
  const source = path.join(stage, name.replace(/\/$/u, ""));
  const data = directory ? Buffer.alloc(0) : fs.readFileSync(source);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  octal(header, 100, 8, mode);
  octal(header, 108, 8, 0);
  octal(header, 116, 8, 0);
  octal(header, 124, 12, data.length);
  octal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = directory ? 0x35 : 0x30;
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  header.write("root", 265, 4, "ascii");
  header.write("root", 297, 4, "ascii");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const checksumText = checksum.toString(8).padStart(6, "0") + "\0 ";
  header.write(checksumText, 148, 8, "ascii");
  chunks.push(header, data);
  if (data.length % 512 !== 0) chunks.push(Buffer.alloc(512 - (data.length % 512)));
}
chunks.push(Buffer.alloc(1024));
const tar = Buffer.concat(chunks);
fs.writeFileSync(archive, zlib.gzipSync(tar, { level: 9, mtime: 0 }));
NODE
}

package_target() {
    local target=$1 binary=$2 output=$3 version suffix stem stage
    version=$(validate_versions "$binary")
    suffix=$(target_suffix "$target")
    stem=herdr-a2a-$version-$suffix
    mkdir -p "$output"
    output=$(CDPATH= cd -- "$output" && pwd -P)
    stage=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-package.XXXXXX")
    stage=$(CDPATH= cd -- "$stage" && pwd -P)
    trap 'rm -rf -- "$stage"' RETURN

    mkdir -p "$stage/bin" "$stage/metadata" "$stage/pi/extensions" "$stage/pi/src" \
        "$stage/pi/skills/herdr-a2a" "$stage/scripts"
    chmod 700 "$stage" "$stage/bin" "$stage/metadata" "$stage/pi" \
        "$stage/pi/extensions" "$stage/pi/src" "$stage/pi/skills" \
        "$stage/pi/skills/herdr-a2a" \
        "$stage/scripts"
    cp "$binary" "$stage/bin/herdr-a2a"
    cp "$repository_root/integrations/pi/package.json" "$stage/pi/package.json"
    cp "$repository_root/integrations/pi/extensions/herdr-a2a.ts" \
        "$stage/pi/extensions/herdr-a2a.ts"
    cp "$repository_root/integrations/pi/src/inbox-pump.ts" \
        "$stage/pi/src/inbox-pump.ts"
    cp "$repository_root/integrations/pi/src/session-client.ts" \
        "$stage/pi/src/session-client.ts"
    cp "$repository_root/integrations/pi/src/team-command.ts" \
        "$stage/pi/src/team-command.ts"
    cp "$repository_root/integrations/pi/skills/herdr-a2a/SKILL.md" \
        "$stage/pi/skills/herdr-a2a/SKILL.md"
    cp "$repository_root/plugins/herdr/scripts/dispatch.sh" "$stage/scripts/dispatch.sh"
    cp "$repository_root/plugins/herdr/scripts/uninstall.sh" "$stage/scripts/uninstall.sh"
    printf '{\n  "schema_version": 3,\n  "plugin_version": "%s",\n  "record_kind": "managed-ownership-template"\n}\n' \
        "$version" > "$stage/metadata/ownership-template.json"
    chmod 700 "$stage/bin/herdr-a2a" "$stage/scripts/dispatch.sh"
    chmod 600 "$stage/metadata/ownership-template.json" "$stage/pi/package.json" \
        "$stage/pi/extensions/herdr-a2a.ts" "$stage/pi/src/inbox-pump.ts" \
        "$stage/pi/src/session-client.ts" \
        "$stage/pi/src/team-command.ts" "$stage/pi/skills/herdr-a2a/SKILL.md" \
        "$stage/scripts/uninstall.sh"

    write_reproducible_archive "$stage" "$output/$stem.tar.gz"
    cp "$binary" "$output/$stem"
    chmod 700 "$output/$stem"
    write_checksum "$output/$stem.tar.gz"
    write_checksum "$output/$stem"
    verify_checksum "$output/$stem.tar.gz" "$output/$stem.tar.gz.sha256" || \
        fail "archive checksum verification failed"
    verify_checksum "$output/$stem" "$output/$stem.sha256" || \
        fail "bootstrap checksum verification failed"
    trap - RETURN
    rm -rf -- "$stage"
}

self_test() {
    local fixture binary first second archive mutated expected actual
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-package-self-test.XXXXXX")
    fixture=$(CDPATH= cd -- "$fixture" && pwd -P)
    self_test_fixture=$fixture
    trap cleanup_self_test EXIT HUP INT TERM
    binary=$fixture/herdr-a2a
    printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'herdr-a2a $(manifest_version)'" > "$binary"
    chmod 700 "$binary"
    first=$fixture/first
    second=$fixture/second
    package_target aarch64-apple-darwin "$binary" "$first"
    package_target aarch64-apple-darwin "$binary" "$second"
    archive=$first/herdr-a2a-$(manifest_version)-macos-arm64.tar.gz
    cmp -s "$archive" "$second/${archive##*/}" || fail "archive is not reproducible"
    expected='bin/
bin/herdr-a2a
metadata/
metadata/ownership-template.json
pi/
pi/extensions/
pi/extensions/herdr-a2a.ts
pi/package.json
pi/src/
pi/src/inbox-pump.ts
pi/src/session-client.ts
pi/src/team-command.ts
pi/skills/
pi/skills/herdr-a2a/
pi/skills/herdr-a2a/SKILL.md
scripts/
scripts/dispatch.sh
scripts/uninstall.sh'
    actual=$(tar -tzf "$archive")
    [[ "$actual" == "$expected" ]] || fail "archive allowlist is not exact"
    verify_checksum "$archive" "$archive.sha256" || fail "valid checksum was rejected"
    mutated=$fixture/mutated.tar.gz
    cp "$archive" "$mutated"
    HERDR_A2A_MUTATED=$mutated node -e \
        'const fs=require("node:fs"); const p=process.env.HERDR_A2A_MUTATED; const b=fs.readFileSync(p); b[Math.floor(b.length/2)]^=1; fs.writeFileSync(p,b)'
    cp "$archive.sha256" "$mutated.sha256"
    printf '%s  %s\n' "$(awk '{ print $1 }' "$archive.sha256")" "${mutated##*/}" > "$mutated.sha256"
    if verify_checksum "$mutated" "$mutated.sha256"; then
        fail "checksum accepted a one-byte mutation"
    fi
    bash "$repository_root/scripts/verify-release-tag-self-test.sh"
    HERDR_A2A_RELEASE_WORKFLOW="$repository_root/.github/workflows/release.yml" node <<'NODE'
const fs = require('node:fs');
const workflow = fs.readFileSync(process.env.HERDR_A2A_RELEASE_WORKFLOW, 'utf8');
const matrix = [...workflow.matchAll(/^\s+- runner: ([^\s]+)\n\s+target: ([^\s]+)$/gm)]
  .map((match) => [match[1], match[2]]);
const expectedMatrix = [
  ['macos-14', 'aarch64-apple-darwin'],
  ['macos-15-intel', 'x86_64-apple-darwin'],
  ['ubuntu-24.04-arm', 'aarch64-unknown-linux-gnu'],
  ['ubuntu-24.04', 'x86_64-unknown-linux-gnu'],
];
if (JSON.stringify(matrix) !== JSON.stringify(expectedMatrix)) {
  throw new Error(`release workflow matrix is not the reviewed four-target runner mapping: ${JSON.stringify(matrix)}`);
}
for (const required of [
  'Verify minimum and latest Pi compatibility',
  'npm ci --prefix integrations/pi',
  'npm install --prefix integrations/pi --no-save --package-lock=false @earendil-works/pi-coding-agent@latest',
  'npm --prefix integrations/pi test',
  'npm --prefix integrations/pi run typecheck',
]) {
  if (!workflow.includes(required)) {
    throw new Error(`release workflow omits the required Pi compatibility lane: ${required}`);
  }
}
const signedTagStep = workflow.match(
  /^\s+- name: Verify trusted signed version tag\n([\s\S]*?)(?=^\s+- (?:name:|uses:)|^  build:)/m,
);
const publishOffset = workflow.indexOf('\n  publish:');
const publishSection = publishOffset === -1 ? '' : workflow.slice(publishOffset);
const verifiesRemoteTag = (step) => step.includes('bash scripts/verify-release-tag.sh')
  && step.includes('--tag "$GITHUB_REF_NAME"')
  && step.includes('--expected-sha "$GITHUB_SHA"')
  && step.includes('--allowed-signers "$RUNNER_TEMP/herdr-a2a-allowed-signers"');
if (signedTagStep === null || !verifiesRemoteTag(signedTagStep[1])) {
  throw new Error('release workflow omits the reviewed pre-build remote signed-tag verifier');
}
const publishVerifier = publishSection.indexOf('bash scripts/verify-release-tag.sh');
const releaseCreate = publishSection.indexOf('gh release create');
if (!verifiesRemoteTag(publishSection)
  || publishVerifier === -1
  || releaseCreate === -1
  || publishVerifier > releaseCreate) {
  throw new Error('release workflow omits the reviewed publish-time remote signed-tag verifier before release creation');
}
const macosRestartStep = workflow.match(
  /^\s+- name: Gate macOS coordinated restart recovery\n([\s\S]*?)(?=^\s+- (?:name:|uses:)|^  publish:)/m,
);
if (macosRestartStep === null
  || !macosRestartStep[1].includes("if: matrix.target == 'aarch64-apple-darwin'")
  || !macosRestartStep[1].includes('CARGO_BUILD_JOBS: 2')
  || !macosRestartStep[1].includes('--features test-harness coordinated_restart_ -- --test-threads=1')
  || !macosRestartStep[1].includes('--test coordinator \\\n            --features test-harness -- --test-threads=1')) {
  throw new Error('release workflow omits the serial feature-gated macOS coordinated-restart lane');
}
const linuxManagedStep = workflow.match(
  /^\s+- name: Gate Linux managed process retirement and rescue\n([\s\S]*?)(?=^\s+- (?:name:|uses:)|^  publish:)/m,
);
if (linuxManagedStep === null
  || !linuxManagedStep[1].includes('--test coordinator \\\n            --features test-harness -- --test-threads=1')) {
  throw new Error('release workflow omits the serial feature-gated Linux coordinator lane');
}
const uses = [...workflow.matchAll(/^\s+- uses: ([^@\s]+)@([^\s]+)(?:\s+#\s+(.+))?$/gm)]
  .map((match) => ({ action: match[1], ref: match[2], comment: match[3] }));
const expectedRefs = new Map([
  ['actions/checkout', '34e114876b0b11c390a56381ad16ebd13914f8d5'],
  ['actions/setup-node', '49933ea5288caeca8642d1e84afbd3f7d6820020'],
  ['actions/upload-artifact', 'ea165f8d65b6e75b540449e92b4886f43607fa02'],
  ['actions/download-artifact', 'd3f86a106a0bac45b974a628896c90dbdf5c8093'],
]);
if (uses.length !== 6) throw new Error(`release workflow has ${uses.length} action uses, expected 6`);
for (const use of uses) {
  if (expectedRefs.get(use.action) !== use.ref || !/^v\d/.test(use.comment ?? '')) {
    throw new Error(`release action is not pinned to its reviewed immutable ref with a version comment: ${use.action}@${use.ref}`);
  }
}
NODE
    printf '%s\n' 'package-release self-test: ok'
}

if [[ ${1:-} == --self-test ]]; then
    [[ $# == 1 ]] || fail "--self-test accepts no other arguments"
    self_test
    exit 0
fi

target=
binary=
output=$repository_root/dist
while (( $# > 0 )); do
    case $1 in
        --target) [[ $# -ge 2 ]] || fail "--target requires a value"; target=$2; shift 2 ;;
        --binary) [[ $# -ge 2 ]] || fail "--binary requires a value"; binary=$2; shift 2 ;;
        --output-dir) [[ $# -ge 2 ]] || fail "--output-dir requires a value"; output=$2; shift 2 ;;
        *) fail "usage: package-release.sh --target <rust-target> --binary <path> [--output-dir <dir>]" ;;
    esac
done
[[ -n "$target" && -n "$binary" ]] || \
    fail "usage: package-release.sh --target <rust-target> --binary <path> [--output-dir <dir>]"
case $binary in /*) ;; *) binary=$repository_root/$binary ;; esac
case $output in /*) ;; *) output=$repository_root/$output ;; esac
package_target "$target" "$binary" "$output"
