#!/usr/bin/env bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -euo pipefail

unset ATOMGIT_TOKEN || true
unset GITHUB_TOKEN || true

token="${PR_LABEL_TOKEN:-}"
pr_iid="${GITCODE_PR_IID:-${pr_id:-}}"
repo="${GITCODE_REPO:-opengauss/oGRAC}"
run_id="${GITCODE_RUN_ID:-${ATOMGIT_WORKFLOW_RUN_ID:-}}"
server="${GITCODE_SERVER_URL:-${ATOMGIT_SERVER_URL:-https://gitcode.com}}"
server="${server%/}"
run_url="${CI_RUN_URL:-}"

if [[ -z "${run_url}" ]]; then
  if [[ -n "${run_id}" ]]; then
    run_url="${server}/${repo}/actions/runs/${run_id}"
  fi
fi

if [[ -z "${token}" ]]; then
  echo "PR_LABEL_TOKEN is empty; skip CI notify comment." >&2
  exit 0
fi
if [[ -z "${pr_iid}" ]]; then
  echo "PR number is empty; skip CI notify comment." >&2
  exit 0
fi
if [[ -z "${run_url}" ]]; then
  echo "CI run URL is empty; skip CI notify comment." >&2
  exit 0
fi

body="$(
  cat <<EOF
| 🚀 CI 流水线已启动 |
| --- |
| 🔗 执行详情: [点击查看流水线](${run_url}) |
EOF
)"

payload="$(
  if command -v python3 >/dev/null 2>&1; then
    PR_COMMENT_BODY="${body}" python3 - <<'PY'
import json
import os
print(json.dumps({"body": os.environ["PR_COMMENT_BODY"]}, ensure_ascii=False))
PY
  elif command -v jq >/dev/null 2>&1; then
    jq -n --arg body "${body}" '{body:$body}'
  else
    # Minimal escape fallback when python/jq are unavailable.
    escaped="${body//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    escaped="${escaped//$'\n'/\\n}"
    printf '{"body":"%s"}' "${escaped}"
  fi
)"

echo "Posting CI started comment to ${repo} PR #${pr_iid}"
echo "run_url=${run_url}"

http_code="$(
  curl -sS -o /tmp/gitcode_ci_notify_resp.json -w '%{http_code}' \
    -X POST "${server}/api/v5/repos/${repo}/pulls/${pr_iid}/comments" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json;charset=UTF-8" \
    -d "${payload}"
)"

echo "HTTP ${http_code}"
if [[ -f /tmp/gitcode_ci_notify_resp.json ]]; then
  cat /tmp/gitcode_ci_notify_resp.json
  echo
fi

case "${http_code}" in
  200|201) exit 0 ;;
  *)
    echo "Failed to post CI notify comment." >&2
    exit 1
    ;;
esac
