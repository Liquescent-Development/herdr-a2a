#!/bin/sh
set -eu

case $0 in
    /*) invoked_path=$0 ;;
    *) invoked_path=$PWD/$0 ;;
esac
script_parent=${invoked_path%/*}
plugin_dir=${script_parent%/*}
helper=$plugin_dir/libexec/herdr-a2a-dispatch
pointer=$plugin_dir/stable-bin-path

# This retained development wrapper is not a lifecycle security boundary. Managed lifecycle
# commands invoke the installer-created native helper directly; that helper validates itself,
# every parent, the pointer, and the stable binary from opened descriptors.
exec "$helper" coordinator dispatch-exec --pointer "$pointer" -- "$@"
