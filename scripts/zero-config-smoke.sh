#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf '%s\n' "zero-config-smoke: $1" >&2
    exit 1
}

[[ ${1:-} == --self-test && $# == 1 ]] || \
    fail "usage: zero-config-smoke.sh --self-test"

repository_root=$(CDPATH= cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export RUST_TEST_THREADS=${RUST_TEST_THREADS:-1}

run_managed_home() {
    local test_name=$1 scenario=$2
    cargo test -p herdr-a2a-cli --features test-harness --test managed_install "$test_name" -- --exact \
        >/dev/null || fail "$scenario home failed"
}

cd "$repository_root"
run_managed_home install_records_ready_state_and_private_native_dispatch_assets clean-install
run_managed_home absent_pi_commits_pending_and_repair_configures_it_once pi-absent
run_managed_home same_source_with_different_pi_entry_is_never_silently_adopted conflicting
run_managed_home update_replaces_only_the_exact_owned_pi_entry_and_owned_files update
run_managed_home source_only_rescue_fails_closed_without_starting_an_interpreter_or_disclosing_a_path rescue
run_managed_home managed_remove_preserves_unowned_pi_configuration_and_durable_data managed-removal

node --test \
    --test-name-pattern='absent or inactive managed plugin leaves the shim silent and inert' \
    integrations/pi/test/extension.test.ts >/dev/null || fail "bare-uninstall home was not inert"

bash scripts/uninstall-self-test.sh >/dev/null || fail "standalone rescue self-test failed"

printf '%s\n' 'zero-config-smoke self-test: ok (clean, Pi-absent, conflicting, install, update, bare uninstall, rescue, managed removal)'
