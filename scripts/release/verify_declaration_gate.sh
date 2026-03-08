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

[[ "$recorded_release" == "$release_tag" ]] || { echo "[ERROR] release= mismatch in fingerprint" >&2; exit 1; }
[[ "$recorded_tag" == "$release_tag" ]] || { echo "[ERROR] release.git.tag mismatch in fingerprint" >&2; exit 1; }

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

latest_manifest_count="$(grep -Eo "latest-manifest.txt" "$dossier_file" | wc -l | tr -d ' ')"
if (( latest_manifest_count < 5 )); then
  echo "[ERROR] Authority dossier must reference all required evidence latest-manifest pointers" >&2
  exit 1
fi

echo "[OK] Release declaration gate passed for ${release_tag}."
