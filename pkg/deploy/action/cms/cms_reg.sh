#!/bin/bash
set +x
set -e

CURRENT_PATH=$(dirname "$(readlink -f "$0")")

if [ $# -lt 1 ]; then
    echo "Usage: ${0##*/} <enable|disable>" >&2
    exit 1
fi

python3 "${CURRENT_PATH}/cms_daemon.py" "$@"
