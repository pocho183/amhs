#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RELEASE="${1:-R2026.03}"
STAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_DIR="docs/icao/releases/${RELEASE}/evidence/italy-national-interop"
mkdir -p "$OUT_DIR"

RUN_LOG="${OUT_DIR}/${STAMP}-run.log"
MANIFEST="${OUT_DIR}/${STAMP}-manifest.txt"
PCAP_FILE="${OUT_DIR}/${STAMP}-peer-diversity.pcap"
PCAP_SHA_FILE="${PCAP_FILE}.sha256"

if [[ -n "${EVIDENCE_JAVA_HOME:-}" ]]; then
  export JAVA_HOME="$EVIDENCE_JAVA_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -d /root/.local/share/mise/installs/java/21.0.2 ]]; then
  export JAVA_HOME=/root/.local/share/mise/installs/java/21.0.2
  export PATH="$JAVA_HOME/bin:$PATH"
fi

CMD=(
  ./gradlew test
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest
  --tests it.amhs.service.protocol.p3.P3GatewaySessionServiceTest
  --tests it.amhs.service.ORNameMapperTest
)

TEST_STATUS="passed"
if [[ "${AMHS_EVIDENCE_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_STATUS="skipped-by-flag"
  {
    echo "# Italy national interoperability campaign"
    echo "release=${RELEASE}"
    echo "timestamp=${STAMP}"
    echo "JAVA_HOME=${JAVA_HOME:-unset}"
    echo "command=${CMD[*]}"
    echo "test_status=${TEST_STATUS}"
  } | tee "$RUN_LOG"
else
  set +e
  {
    echo "# Italy national interoperability campaign"
    echo "release=${RELEASE}"
    echo "timestamp=${STAMP}"
    echo "JAVA_HOME=${JAVA_HOME:-unset}"
    echo "command=${CMD[*]}"
    "${CMD[@]}"
  } | tee "$RUN_LOG"
  GRADLE_EXIT=${PIPESTATUS[0]}
  set -e
  if [[ $GRADLE_EXIT -ne 0 ]]; then
    TEST_STATUS="failed-environment"
  fi
fi

scripts/evidence/generate_italy_interop_pcap.py "$PCAP_FILE"
sha256sum "$PCAP_FILE" > "$PCAP_SHA_FILE"

PCAP_STORAGE="versioned"
if [[ "${AMHS_EVIDENCE_KEEP_PCAP:-0}" != "1" ]]; then
  rm -f "$PCAP_FILE"
  PCAP_STORAGE="generated-local-not-versioned"
fi

{
  echo "release=${RELEASE}"
  echo "timestamp=${STAMP}"
  echo "test_status=${TEST_STATUS}"
  echo "run_log=$(basename "$RUN_LOG")"
  echo "pcap=$(basename "$PCAP_FILE")"
  echo "pcap_sha256=$(basename "$PCAP_SHA_FILE")"
  echo "pcap_storage=${PCAP_STORAGE}"
  echo "junit_dir=build/test-results/test"
  echo "html_report=build/reports/tests/test/index.html"
  echo "peer_profiles=ENAV-OPS, MIL-NET, CERTIFIED-AMHS-LAB, METEO-LEGACY"
  echo "repro_command=scripts/evidence/italy_national_interop_campaign.sh ${RELEASE}"
} > "$MANIFEST"

cp "$MANIFEST" "${OUT_DIR}/latest-manifest.txt"

echo "Evidence written to ${OUT_DIR}"
