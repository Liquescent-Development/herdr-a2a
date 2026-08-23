#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() {
    printf '%s\n' "verify-release-tag: $1" >&2
    exit 1
}

usage() {
    fail 'usage: verify-release-tag.sh --tag vMAJOR.MINOR.PATCH --expected-sha SHA --allowed-signers FILE [--remote NAME] [--repository DIRECTORY]'
}

tag=
expected_sha=
allowed_signers=
remote=origin
repository=.
while (( $# > 0 )); do
    case $1 in
        --tag) [[ $# -ge 2 ]] || usage; tag=$2; shift 2 ;;
        --expected-sha) [[ $# -ge 2 ]] || usage; expected_sha=$2; shift 2 ;;
        --allowed-signers) [[ $# -ge 2 ]] || usage; allowed_signers=$2; shift 2 ;;
        --remote) [[ $# -ge 2 ]] || usage; remote=$2; shift 2 ;;
        --repository) [[ $# -ge 2 ]] || usage; repository=$2; shift 2 ;;
        *) usage ;;
    esac
done

(( ${#tag} <= 30 )) || fail 'tag exceeds the 30-character release bound'
[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
    fail 'tag must be a bounded semantic version in vMAJOR.MINOR.PATCH form'
[[ "$tag" =~ ^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]] || \
    fail 'tag component exceeds the 9-digit release bound'
[[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'expected SHA must be a lowercase 40-hex commit ID'
[[ -d "$repository/.git" || -f "$repository/.git" ]] || fail 'repository is not a Git worktree'
[[ -r "$allowed_signers" && -s "$allowed_signers" ]] || fail 'allowed-signers file must exist and be non-empty'
git -C "$repository" remote get-url "$remote" >/dev/null 2>&1 || fail 'configured remote is required'

verification_ref="refs/herdr-a2a/verify-tags/${tag}.$$.${RANDOM}"
git -C "$repository" show-ref --verify --quiet "$verification_ref" && \
    fail 'temporary verification ref unexpectedly already exists'
cleanup_verification_ref=0
cleanup() {
    if (( cleanup_verification_ref )); then
        git -C "$repository" update-ref -d "$verification_ref" || true
    fi
}
trap cleanup EXIT HUP INT TERM

git -C "$repository" fetch --no-tags --force "$remote" \
    "refs/tags/$tag:$verification_ref" || fail 'could not fetch exact remote tag into verification ref'
cleanup_verification_ref=1

object_type=$(git -C "$repository" cat-file -t "$verification_ref" 2>/dev/null) || \
    fail 'fetched verification ref is missing'
[[ "$object_type" == tag ]] || fail 'remote tag object must be an annotated tag'
git -C "$repository" \
    -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile="$allowed_signers" \
    verify-tag "$verification_ref" || fail 'trusted signed tag verification failed'

peeled_commit=$(git -C "$repository" rev-parse "$verification_ref^{}") || \
    fail 'annotated tag could not be peeled'
[[ $(git -C "$repository" cat-file -t "$peeled_commit") == commit ]] || \
    fail 'annotated tag must peel to a commit'
[[ "$peeled_commit" == "$expected_sha" ]] || fail 'peeled tag commit does not match expected SHA'

printf '%s\n' "verify-release-tag: verified $tag at $expected_sha"
