#!/usr/bin/env bash
# Offline installed-package fixture checks. Setup is documented in REVIEW_BRIEF.md.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
audit_python="${CPR_AUDIT_PYTHON:-python3}"
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 2; }
audit_python="$(command -v "$audit_python")"
if [[ "$audit_python" != /* ]]; then audit_python="$PWD/$audit_python"; fi
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cpr-audit.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
cd "$scratch"
unset PYTHONPATH

"$audit_python" -c 'import importlib.metadata, pathlib, sys, continuity_receipt
package = pathlib.Path(continuity_receipt.__file__).resolve()
if package.is_relative_to(pathlib.Path(sys.argv[1]).resolve()):
    raise SystemExit("install a wheel or a non-editable package first; source import refused")
print("package_version=" + importlib.metadata.version("continuity-receipt"))
print("package_path=" + str(package))' "$repo_root"

checked=0
for manifest in manifest.json manifest-0.5.json manifest-0.6.json; do
  jq -er '.vectors[] | [.file, .expected_verdict, (.expected_code // "-"), .require_anchor] | @tsv' \
    "$repo_root/vectors/$manifest" > "$scratch/entries.tsv"
  while IFS=$'\t' read -r fixture verdict expected_code require_anchor; do
    args=("$repo_root/vectors/$fixture")
    if [[ "$require_anchor" == true ]]; then args+=(--require-anchor); fi
    if "$audit_python" -m continuity_receipt.verify "${args[@]}" > result.json 2> result.stderr; then
      actual_rc=0
    else
      actual_rc=$?
    fi
    expected_rc=1
    if [[ "$verdict" == TRUSTED ]]; then expected_rc=0; fi
    [[ "$actual_rc" == "$expected_rc" ]] || {
      cat result.json result.stderr >&2
      echo "$manifest/$fixture: exit $actual_rc, expected $expected_rc" >&2
      exit 1
    }
    if ! jq -se --arg verdict "$verdict" --arg code "$expected_code" \
      'length == 1 and (.[0] | .verdict == $verdict and ($code == "-" or any(.errors[]; .code == $code)))' \
      result.json >/dev/null; then
      cat result.json result.stderr >&2
      echo "$manifest/$fixture: expected $verdict with code $expected_code" >&2
      exit 1
    fi
    printf 'PASS %s/%s %s exit=%s\n' "$manifest" "$fixture" "$verdict" "$actual_rc"
    checked=$((checked + 1))
  done < "$scratch/entries.tsv"
done

jq -er '.vectors[] | [.file, .expected_valid, (.bundle_file // "-"), (.revocations_file // "-"), (.expected_errors | sort | tojson)] | @tsv' \
  "$repo_root/vectors/verification/manifest.json" > "$scratch/receipts.tsv"
while IFS=$'\t' read -r fixture valid bundle revocations expected_errors; do
  args=("$repo_root/vectors/verification/$fixture")
  if [[ "$bundle" != - ]]; then args+=(--bundle "$repo_root/vectors/verification/$bundle"); fi
  if [[ "$revocations" != - ]]; then args+=(--revocations "$repo_root/vectors/verification/$revocations"); fi
  if "$audit_python" -m continuity_receipt.verification "${args[@]}" > result.json 2> result.stderr; then
    actual_rc=0
  else
    actual_rc=$?
  fi
  expected_rc=1
  if [[ "$valid" == true ]]; then expected_rc=0; fi
  [[ "$actual_rc" == "$expected_rc" ]] || {
    cat result.json result.stderr >&2
    echo "verification/$fixture: exit $actual_rc, expected $expected_rc" >&2
    exit 1
  }
  if ! jq -se --argjson valid "$valid" --argjson errors "$expected_errors" \
    'length == 1 and (.[0] | .valid == $valid and ((.errors | sort) == $errors))' result.json >/dev/null; then
    cat result.json result.stderr >&2
    echo "verification/$fixture: expected valid=$valid with errors $expected_errors" >&2
    exit 1
  fi
  printf 'PASS verification/%s valid=%s exit=%s\n' "$fixture" "$valid" "$actual_rc"
  checked=$((checked + 1))
done < "$scratch/receipts.tsv"
printf 'PASS installed-package fixture checks=%s\n' "$checked"
