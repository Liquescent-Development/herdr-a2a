#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "verify-release-tag self-test: $1" >&2
    exit 1
}

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
fixture=

cleanup() {
    if [[ -n "$fixture" && -d "$fixture" ]]; then
        rm -rf -- "$fixture"
    fi
}

expect_failure() {
    local expected=$1
    shift
    local output
    if output=$("$@" 2>&1); then
        fail "expected failure containing: $expected"
    fi
    [[ "$output" == *"$expected"* ]] || fail "unexpected failure: $output"
}

remote_tag_oid() {
    git --git-dir="$origin" rev-parse "refs/tags/$1"
}

remote_tag_type() {
    git --git-dir="$origin" cat-file -t "refs/tags/$1"
}

assert_remote_tag_unchanged() {
    local tag=$1 expected_oid=$2 expected_type=$3
    [[ $(remote_tag_oid "$tag") == "$expected_oid" ]] || fail "verifier mutated remote $tag"
    [[ $(remote_tag_type "$tag") == "$expected_type" ]] || fail "verifier changed remote $tag type"
}

assert_checkout_tag_remains_peeled() {
    [[ $(git -C "$consumer" rev-parse refs/tags/v0.1.5) == "$checkout_tag_oid" ]] || \
        fail 'verifier changed the checkout tag ref'
    [[ $(git -C "$consumer" cat-file -t refs/tags/v0.1.5) == "$checkout_tag_type" ]] || \
        fail 'verifier changed the checkout tag type'
}

fixture=$(mktemp -d "${TMPDIR:-/tmp}/herdr-a2a-verify-release-tag.XXXXXX")
trap cleanup EXIT HUP INT TERM
origin=$fixture/origin.git
source_repo=$fixture/source
consumer=$fixture/consumer
signing_key=$fixture/release-signing
allowed_signers=$fixture/allowed-signers

git init --bare -q "$origin"
git init -q -b main "$source_repo"
git -C "$source_repo" config user.name 'Release Test'
git -C "$source_repo" config user.email 'release-test@example.test'
git -C "$source_repo" config commit.gpgsign false
printf '%s\n' 'release source' > "$source_repo/README"
git -C "$source_repo" add README
git -C "$source_repo" commit -q -m 'release source'
git -C "$source_repo" remote add origin "$origin"
git -C "$source_repo" push -q origin main

ssh-keygen -q -t ed25519 -N '' -f "$signing_key"
awk '{ print "release-test@example.test " $1 " " $2 }' "$signing_key.pub" > "$allowed_signers"
git -C "$source_repo" config gpg.format ssh
git -C "$source_repo" config user.signingkey "$signing_key"
git -C "$source_repo" tag -s -a v0.1.5 -m 'signed v0.1.5'
git -C "$source_repo" push -q origin refs/tags/v0.1.5

git clone -q "$origin" "$consumer"
expected_sha=$(git -C "$source_repo" rev-parse v0.1.5^{})
remote_v015_oid=$(remote_tag_oid v0.1.5)
remote_v015_type=$(remote_tag_type v0.1.5)
[[ "$remote_v015_type" == tag ]] || fail 'fixture tag is not annotated'

# Simulate checkout force-replacing the local annotated tag with its peeled commit.
git -C "$consumer" update-ref refs/tags/v0.1.5 "$expected_sha"
[[ $(git -C "$consumer" cat-file -t refs/tags/v0.1.5) == commit ]] || fail 'local tag overwrite was not simulated'
checkout_tag_oid=$(git -C "$consumer" rev-parse refs/tags/v0.1.5)
checkout_tag_type=$(git -C "$consumer" cat-file -t refs/tags/v0.1.5)

bash "$repository_root/scripts/verify-release-tag.sh" \
    --tag v0.1.5 \
    --expected-sha "$expected_sha" \
    --remote origin \
    --allowed-signers "$allowed_signers" \
    --repository "$consumer"

assert_checkout_tag_remains_peeled
assert_remote_tag_unchanged v0.1.5 "$remote_v015_oid" "$remote_v015_type"

git -C "$source_repo" tag v0.1.6
git -C "$source_repo" push -q origin refs/tags/v0.1.6
remote_v016_oid=$(remote_tag_oid v0.1.6)
remote_v016_type=$(remote_tag_type v0.1.6)
expect_failure 'remote tag object must be an annotated tag' \
    bash "$repository_root/scripts/verify-release-tag.sh" \
    --tag v0.1.6 \
    --expected-sha "$expected_sha" \
    --remote origin \
    --allowed-signers "$allowed_signers" \
    --repository "$consumer"
assert_checkout_tag_remains_peeled
assert_remote_tag_unchanged v0.1.5 "$remote_v015_oid" "$remote_v015_type"
assert_remote_tag_unchanged v0.1.6 "$remote_v016_oid" "$remote_v016_type"

oversized_tag=v1234567890.1234567890.1234567890
expect_failure 'tag exceeds the 30-character release bound' \
    bash "$repository_root/scripts/verify-release-tag.sh" \
    --tag "$oversized_tag" \
    --expected-sha "$expected_sha" \
    --remote origin \
    --allowed-signers "$allowed_signers" \
    --repository "$consumer"
assert_checkout_tag_remains_peeled
assert_remote_tag_unchanged v0.1.5 "$remote_v015_oid" "$remote_v015_type"
assert_remote_tag_unchanged v0.1.6 "$remote_v016_oid" "$remote_v016_type"

overwide_component_tag=v1234567890.1.1
expect_failure 'tag component exceeds the 9-digit release bound' \
    bash "$repository_root/scripts/verify-release-tag.sh" \
    --tag "$overwide_component_tag" \
    --expected-sha "$expected_sha" \
    --remote origin \
    --allowed-signers "$allowed_signers" \
    --repository "$consumer"
assert_checkout_tag_remains_peeled
assert_remote_tag_unchanged v0.1.5 "$remote_v015_oid" "$remote_v015_type"
assert_remote_tag_unchanged v0.1.6 "$remote_v016_oid" "$remote_v016_type"

printf '%s\n' 'different commit' > "$source_repo/next"
git -C "$source_repo" add next
git -C "$source_repo" commit -q -m 'different expected commit'
wrong_expected_sha=$(git -C "$source_repo" rev-parse HEAD)
expect_failure 'peeled tag commit does not match expected SHA' \
    bash "$repository_root/scripts/verify-release-tag.sh" \
    --tag v0.1.5 \
    --expected-sha "$wrong_expected_sha" \
    --remote origin \
    --allowed-signers "$allowed_signers" \
    --repository "$consumer"

assert_checkout_tag_remains_peeled
assert_remote_tag_unchanged v0.1.5 "$remote_v015_oid" "$remote_v015_type"
assert_remote_tag_unchanged v0.1.6 "$remote_v016_oid" "$remote_v016_type"
printf '%s\n' 'verify-release-tag self-test: ok'
