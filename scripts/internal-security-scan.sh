#!/usr/bin/env bash
set -euo pipefail

require_scan="${VULCANSTRACE_REQUIRE_INTERNAL_SCAN:-0}"
api_url="${VULCANSTRACE_INTERNAL_VULN_API:-}"
api_token="${VULCANSTRACE_INTERNAL_VULN_TOKEN:-}"

if [[ -z "${api_url}" ]]; then
  if [[ "${require_scan}" == "1" ]]; then
    echo "VULCANSTRACE_INTERNAL_VULN_API is required but not set." >&2
    exit 1
  fi
  echo "Internal scan skipped (VULCANSTRACE_INTERNAL_VULN_API not set)."
  exit 0
fi

if [[ -z "${api_token}" ]]; then
  echo "VULCANSTRACE_INTERNAL_VULN_TOKEN is required to run the internal scan." >&2
  exit 1
fi

tmpfile="$(mktemp)"
trap 'rm -f "${tmpfile}"' EXIT

dotnet list VulcansTrace.Linux.sln package --include-transitive > "${tmpfile}"

printf 'Authorization: Bearer %s\n' "${api_token}" | \
  curl -sS \
    -H @- \
    -F "report=@${tmpfile}" \
    "${api_url}"

echo "Internal vulnerability scan completed."
