# This installed recovery notice is deliberately mode 0600 and source-only. An executable
# shebang cannot clear ELF loader variables before Linux starts its interpreter.
if [ "${BASH_SOURCE[0]-}" = "$0" ]; then
    printf '%s\n' "herdr-a2a uninstall: rescue_unavailable: source this recovery notice; do not execute it" >&2
    exit 1
fi

for argument in "$@"; do
    case $argument in
        --purge|--skip-herdr-unregister) ;;
        *)
            printf '%s\n' "herdr-a2a uninstall: invalid_argument" >&2
            return 1
            ;;
    esac
done

printf '%s\n' \
    "herdr-a2a uninstall: rescue_unavailable: use the authenticated managed CLI's 'managed remove' command; restore or reinstall it if validation fails" >&2
return 1
