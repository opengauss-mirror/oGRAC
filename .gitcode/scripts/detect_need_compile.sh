#!/usr/bin/env bash
###############################################################
##  Decide need_compile without official checkout action.    ##
##  Prefer PR files API (Bearer). Fallback: git fetch of     ##
##  public MR head vs target. Avoid HTTP password auth.      ##
###############################################################
set -euo pipefail

pr_iid="${GITCODE_PR_IID:-${pr_id:-}}"
repo="${GITCODE_REPO:-opengauss/oGRAC}"
target="${GITCODE_TARGET_BRANCH:-master}"
target="${target#refs/heads/}"
token="${PR_LABEL_TOKEN:-}"
server="${GITCODE_SERVER_URL:-${ATOMGIT_SERVER_URL:-https://gitcode.com}}"
server="${server%/}"
out="${ATOMGIT_OUTPUT:-}"

files=""
need_compile=no

list_files_via_api() {
  if [[ -z "${pr_iid}" || -z "${token}" ]]; then
    return 0
  fi
  echo "List PR files via API: ${repo}#${pr_iid}"
  set +e
  files="$(
    curl -sS \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json;charset=UTF-8" \
      "${server}/api/v5/repos/${repo}/pulls/${pr_iid}/files" \
    | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(data, list):
    sys.exit(0)
for item in data:
    name = item.get("filename") or item.get("file_path") or ""
    if name:
        print(name)
'
  )"
  set -e
}

list_files_via_git() {
  if [[ -z "${pr_iid}" ]]; then
    return 0
  fi
  echo "PR files API empty; fallback to git diff ${target}...MR head"
  local work host
  work="$(mktemp -d)"
  trap "rm -rf '${work}'" RETURN

  host="${server#https://}"
  host="${host#http://}"

  git -C "${work}" init -q
  git -C "${work}" remote add origin "${server}/${repo}.git"

  set +e
  if ! git -C "${work}" fetch --no-tags --depth=50 origin \
      "refs/merge-requests/${pr_iid}/head:mr-head" \
      "refs/heads/${target}:target-branch"; then
    if [[ -n "${token}" ]]; then
      echo "Anonymous fetch failed; retry with oauth2 PAT"
      git -C "${work}" remote set-url origin "https://oauth2:${token}@${host}/${repo}.git"
      git -C "${work}" fetch --no-tags --depth=50 origin \
        "refs/merge-requests/${pr_iid}/head:mr-head" \
        "refs/heads/${target}:target-branch"
    fi
  fi
  if git -C "${work}" rev-parse --verify mr-head >/dev/null 2>&1 \
    && git -C "${work}" rev-parse --verify target-branch >/dev/null 2>&1; then
    files="$(git -C "${work}" diff --name-only target-branch...mr-head)"
  fi
  set -e
}

list_files_via_api
if [[ -z "${files}" ]]; then
  list_files_via_git
fi

echo "changed files:"
printf '%s\n' "${files}"

if [[ -z "${files}" ]]; then
  echo "cannot determine changed files; compile to be safe"
  need_compile=yes
else
  while IFS= read -r f || [[ -n "${f}" ]]; do
    [[ -z "${f}" ]] && continue
    case "${f}" in
      *.md|*.rst|*.log|*.png|*.jpg|*.doc|*.eddx|*.svg|*.yml|*.yaml) continue ;;
      .gitcode/*) continue ;;
    esac
    echo "non-doc file: ${f}"
    need_compile=yes
    break
  done <<< "${files}"
fi

echo "need_compile=${need_compile}"
if [[ -n "${out}" ]]; then
  echo "need_compile=${need_compile}" >> "${out}"
fi
