#!/bin/bash
set +x

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
exec bash "${CURRENT_PATH}/../wsr/gen_report.sh" --config "${CURRENT_PATH}/report.cnf" "$@"
