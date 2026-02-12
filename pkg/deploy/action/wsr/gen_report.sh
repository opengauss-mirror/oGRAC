#!/bin/bash
set +x

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
exec python3 -B "${CURRENT_PATH}/gen_report.py" "$@"
