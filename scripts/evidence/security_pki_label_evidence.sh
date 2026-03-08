#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <release-tag>"
  exit 1
fi


if [[ -z "${JAVA_HOME:-}" && -x "/root/.local/share/mise/installs/java/21.0.2/bin/java" ]]; then
  export JAVA_HOME="/root/.local/share/mise/installs/java/21.0.2"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

release_tag="$1"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
evidence_dir="$repo_root/docs/icao/releases/${release_tag}/evidence/security-pki-label"
mkdir -p "$evidence_dir"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_log="$evidence_dir/${timestamp}-run.log"
manifest="$evidence_dir/${timestamp}-manifest.txt"
latest_manifest="$evidence_dir/latest-manifest.txt"

cd "$repo_root"

{
  echo "[INFO] security evidence run timestamp=$timestamp release=$release_tag"
  echo "[INFO] command=./gradlew --no-daemon test --tests it.amhs.security.TLSContextFactoryTest --tests it.amhs.compliance.SecurityLabelPolicyTest --tests it.amhs.compliance.AMHSComplianceValidatorTest"
  ./gradlew --no-daemon test \
    --tests it.amhs.security.TLSContextFactoryTest \
    --tests it.amhs.compliance.SecurityLabelPolicyTest \
    --tests it.amhs.compliance.AMHSComplianceValidatorTest
} >"$run_log" 2>&1

{
  echo "release=$release_tag"
  echo "timestamp=$timestamp"
  echo "run.log=$(basename "$run_log")"
  if [[ -f "$repo_root/build/test-results/test/TEST-it.amhs.security.TLSContextFactoryTest.xml" ]]; then
    cp "$repo_root/build/test-results/test/TEST-it.amhs.security.TLSContextFactoryTest.xml" "$evidence_dir/${timestamp}-TEST-it.amhs.security.TLSContextFactoryTest.xml"
    echo "junit.tls=$(basename "$evidence_dir/${timestamp}-TEST-it.amhs.security.TLSContextFactoryTest.xml")"
  fi
  if [[ -f "$repo_root/build/test-results/test/TEST-it.amhs.compliance.SecurityLabelPolicyTest.xml" ]]; then
    cp "$repo_root/build/test-results/test/TEST-it.amhs.compliance.SecurityLabelPolicyTest.xml" "$evidence_dir/${timestamp}-TEST-it.amhs.compliance.SecurityLabelPolicyTest.xml"
    echo "junit.securityLabel=$(basename "$evidence_dir/${timestamp}-TEST-it.amhs.compliance.SecurityLabelPolicyTest.xml")"
  fi
  if [[ -f "$repo_root/build/test-results/test/TEST-it.amhs.compliance.AMHSComplianceValidatorTest.xml" ]]; then
    cp "$repo_root/build/test-results/test/TEST-it.amhs.compliance.AMHSComplianceValidatorTest.xml" "$evidence_dir/${timestamp}-TEST-it.amhs.compliance.AMHSComplianceValidatorTest.xml"
    echo "junit.identityBinding=$(basename "$evidence_dir/${timestamp}-TEST-it.amhs.compliance.AMHSComplianceValidatorTest.xml")"
  fi

  (cd "$evidence_dir" && (shasum -a 256 "$(basename "$run_log")" 2>/dev/null || sha256sum "$(basename "$run_log")"))
} >"$manifest"

cp "$manifest" "$latest_manifest"
echo "[INFO] security evidence published: $manifest"
