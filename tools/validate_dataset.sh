#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

for jsonl_file in telemetry/*.jsonl identity/*.jsonl source_control/*.jsonl; do
  [ -f "$jsonl_file" ] || continue
  while IFS= read -r record; do
    printf '%s' "$record" | jq -e . >/dev/null
  done < "$jsonl_file"
done

required=(
  "review-board-portal.com"
  "45.83.64.19"
  "cdn-build-linker.com"
  "hotfix/cache-key"
  "AssumeRoleWithWebIdentity"
  "/prod/export/box_token"
  "regulated_delta.7z"
  "192.0.2.77"
)

for marker in "${required[@]}"; do
  if ! grep -R -F -q -- "$marker" telemetry artifacts identity source_control saas network endpoint cloud 2>/dev/null; then
    echo "missing required evidence marker: $marker" >&2
    exit 1
  fi
done

echo "dataset validation passed"
