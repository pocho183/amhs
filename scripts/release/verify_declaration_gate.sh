#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <release-tag>" >&2
  exit 64
fi

release_tag="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_dir="$repo_root/docs/icao/releases/${release_tag}"
fingerprint_file="$release_dir/CONFIGURATION_FINGERPRINT.txt"
manifest_file="$release_dir/DECLARATION_ARTIFACT_MANIFEST.txt"
dossier_file="$release_dir/AUTHORITY_DECLARATION_DOSSIER.md"
conformance_map="$repo_root/docs/icao/ICAO_ATN_PROFILE_REQUIREMENT_TRACEABILITY.md"

require_file() {
  local file="$1"
  [[ -f "$file" ]] || { echo "[ERROR] Missing required file: $file" >&2; exit 1; }
}

require_binding() {
  local key="$1"
  local file="$2"
  if ! grep -Eq "^${key}=" "$file"; then
    echo "[ERROR] Missing required key '${key}' in ${file}" >&2
    exit 1
  fi
}

require_file "$fingerprint_file"
require_file "$manifest_file"
require_file "$dossier_file"
require_file "$conformance_map"

require_binding "release" "$manifest_file"
require_binding "generated_utc" "$manifest_file"
require_binding "artifact_manifest_version" "$manifest_file"

require_binding "release" "$fingerprint_file"
require_binding "release.git.tag" "$fingerprint_file"
require_binding "release.git.commit" "$fingerprint_file"
require_binding "release.artifact.manifest.path" "$fingerprint_file"
require_binding "release.artifact.manifest.sha256" "$fingerprint_file"
require_binding "release.runtime.profile.sha256" "$fingerprint_file"
require_binding "release.active.feature-flags" "$fingerprint_file"

recorded_release="$(awk -F= '/^release=/{print $2}' "$fingerprint_file")"
recorded_tag="$(awk -F= '/^release.git.tag=/{print $2}' "$fingerprint_file")"
recorded_commit="$(awk -F= '/^release.git.commit=/{print $2}' "$fingerprint_file")"
recorded_manifest_path="$(awk -F= '/^release.artifact.manifest.path=/{print $2}' "$fingerprint_file")"
recorded_manifest_sha="$(awk -F= '/^release.artifact.manifest.sha256=/{print $2}' "$fingerprint_file")"
manifest_release="$(awk -F= '/^release=/{print $2}' "$manifest_file")"

[[ "$recorded_release" == "$release_tag" ]] || { echo "[ERROR] release= mismatch in fingerprint" >&2; exit 1; }
[[ "$recorded_tag" == "$release_tag" ]] || { echo "[ERROR] release.git.tag mismatch in fingerprint" >&2; exit 1; }
[[ "$manifest_release" == "$release_tag" ]] || { echo "[ERROR] release= mismatch in declaration artifact manifest" >&2; exit 1; }

if ! git -C "$repo_root" rev-parse --verify "$release_tag^{tag}" >/dev/null 2>&1; then
  echo "[ERROR] Required annotated tag '$release_tag' is not present in git metadata" >&2
  exit 1
fi

resolved_tag_commit="$(git -C "$repo_root" rev-list -n 1 "$release_tag")"
[[ "$recorded_commit" == "$resolved_tag_commit" ]] || {
  echo "[ERROR] release.git.commit (${recorded_commit}) does not match tagged commit (${resolved_tag_commit})" >&2
  exit 1
}

if [[ "$recorded_manifest_path" != "docs/icao/releases/${release_tag}/DECLARATION_ARTIFACT_MANIFEST.txt" ]]; then
  echo "[ERROR] Manifest path in fingerprint is not release-scoped" >&2
  exit 1
fi

computed_manifest_sha="$(sha256sum "$manifest_file" | awk '{print $1}')"
[[ "$computed_manifest_sha" == "$recorded_manifest_sha" ]] || {
  echo "[ERROR] Manifest SHA mismatch in fingerprint" >&2
  exit 1
}

required_manifest_artifacts=(
  "docs/icao/releases/${release_tag}/AUTHORITY_DECLARATION_DOSSIER.md"
  "docs/icao/releases/${release_tag}/PICS_${release_tag}.md"
  "docs/icao/releases/${release_tag}/PIXIT_${release_tag}.md"
  "docs/icao/releases/${release_tag}/evidence/p3-negative-apdu/latest-manifest.txt"
  "docs/icao/releases/${release_tag}/evidence/p1-dr-ndr-interop/latest-manifest.txt"
  "docs/icao/releases/${release_tag}/evidence/italy-national-interop/latest-manifest.txt"
  "docs/icao/releases/${release_tag}/evidence/atn-pki-runtime-enforcement/latest-manifest.txt"
  "docs/icao/releases/${release_tag}/evidence/operational-assurance/latest-manifest.txt"
)

for required_artifact in "${required_manifest_artifacts[@]}"; do
  if ! grep -Eq "^[[:xdigit:]]{64}[[:space:]]+${required_artifact}$" "$manifest_file"; then
    echo "[ERROR] Manifest is missing required release artifact: ${required_artifact}" >&2
    exit 1
  fi
done

manifest_entries="$(awk '/^[[:xdigit:]]{64}[[:space:]]+/{count++} END {print count+0}' "$manifest_file")"
if (( manifest_entries < ${#required_manifest_artifacts[@]} )); then
  echo "[ERROR] Manifest has insufficient artifact entries (${manifest_entries})" >&2
  exit 1
fi

while read -r expected_sha artifact_path; do
  [[ -n "${expected_sha:-}" && -n "${artifact_path:-}" ]] || continue
  artifact_abs_path="$repo_root/$artifact_path"
  if [[ ! -f "$artifact_abs_path" ]]; then
    echo "[ERROR] Manifest references missing file: ${artifact_path}" >&2
    exit 1
  fi

  computed_sha="$(sha256sum "$artifact_abs_path" | awk '{print $1}')"
  if [[ "$computed_sha" != "$expected_sha" ]]; then
    echo "[ERROR] Manifest digest mismatch for ${artifact_path}" >&2
    exit 1
  fi
done < <(awk '/^[[:xdigit:]]{64}[[:space:]]+/{print $1, $2}' "$manifest_file")

latest_manifest_count="$(grep -Eo "latest-manifest.txt" "$dossier_file" | wc -l | tr -d ' ')"
if (( latest_manifest_count < 5 )); then
  echo "[ERROR] Authority dossier must reference all required evidence latest-manifest pointers" >&2
  exit 1
fi

map_rows="$(awk '
  /^## 4\. Single-source requirement-to-evidence matrix/ {in_section=1; next}
  /^## / && in_section {in_section=0}
  in_section && /^\|/ {
    line=$0
    gsub(/^\|[[:space:]]*/, "", line)
    gsub(/[[:space:]]*\|$/, "", line)
    n=split(line, cols, /[[:space:]]*\|[[:space:]]*/)
    if (n < 6) next
    if (cols[1] == "Requirement ID" || cols[1] ~ /^-+$/) next
    printf "%s\t%s\t%s\t%s\n", cols[1], tolower(cols[2]), cols[4], cols[5]
  }
' "$conformance_map" || true)"

[[ -n "$map_rows" ]] || {
  echo "[ERROR] Conformance map section 4 has no declaration rows: $conformance_map" >&2
  exit 1
}

has_p1=0
has_p3=0
has_security=0
has_operational=0

while IFS=$'\t' read -r requirement_id control_family governing_sections evidence_artifacts; do
  [[ -n "$requirement_id" ]] || continue

  if [[ -z "$governing_sections" || "$governing_sections" == "-" ]]; then
    echo "[ERROR] ${requirement_id} is missing governing document section references" >&2
    exit 1
  fi
  if [[ "$governing_sections" != *"§"* ]]; then
    echo "[ERROR] ${requirement_id} governing references must include section anchors (e.g., §n)" >&2
    exit 1
  fi

  if [[ -z "$evidence_artifacts" || "$evidence_artifacts" == "-" ]]; then
    echo "[ERROR] ${requirement_id} is missing executable evidence references" >&2
    exit 1
  fi
  if ! [[ "$evidence_artifacts" =~ (\./gradlew[[:space:]]+test|\.log|\.pcap|\.pcap\.sha256) ]]; then
    echo "[ERROR] ${requirement_id} evidence must include at least one executable test/log/pcap artifact" >&2
    exit 1
  fi

  [[ "$control_family" == *"p1"* ]] && has_p1=1
  [[ "$control_family" == *"p3"* ]] && has_p3=1
  [[ "$control_family" == *"security"* ]] && has_security=1
  [[ "$control_family" == *"operational"* ]] && has_operational=1
done <<< "$map_rows"

(( has_p1 == 1 )) || { echo "[ERROR] Conformance map must include at least one P1 declaration row" >&2; exit 1; }
(( has_p3 == 1 )) || { echo "[ERROR] Conformance map must include at least one P3 declaration row" >&2; exit 1; }
(( has_security == 1 )) || { echo "[ERROR] Conformance map must include at least one security declaration row" >&2; exit 1; }
(( has_operational == 1 )) || { echo "[ERROR] Conformance map must include at least one operational declaration row" >&2; exit 1; }

echo "[OK] Release declaration gate passed for ${release_tag}."
