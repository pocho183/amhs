#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${EVIDENCE_JAVA_HOME:-}" ]]; then
  export JAVA_HOME="$EVIDENCE_JAVA_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -d /root/.local/share/mise/installs/java/21.0.2 ]]; then
  export JAVA_HOME=/root/.local/share/mise/installs/java/21.0.2
  export PATH="$JAVA_HOME/bin:$PATH"
fi

RELEASE_ID="${1:-R$(date -u +%Y.%m)}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK_DIR="build/evidence/releases/${RELEASE_ID}/p3-negative-apdu/${STAMP}"
PUBLISH_DIR="docs/icao/releases/${RELEASE_ID}/evidence/p3-negative-apdu"

mkdir -p "$WORK_DIR" "$PUBLISH_DIR"

LOG_FILE="${WORK_DIR}/run.log"
CMD=(
  ./gradlew test
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest
  --tests it.amhs.service.CotpConnectionTpduTest
  --tests it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseDiagnosticsTest
)

set +e
{
  echo "# p3 negative apdu regression"
  echo "release=${RELEASE_ID}"
  date -u +"%Y-%m-%dT%H:%M:%SZ"
  echo "JAVA_HOME=${JAVA_HOME:-unset}"
  echo "command: ${CMD[*]}"
  "${CMD[@]}" 2>&1
} | tee "$LOG_FILE"
RESULT=$?
set -e

cp "$LOG_FILE" "${PUBLISH_DIR}/${STAMP}-run.log"

ARTIFACTS=("${STAMP}-run.log")
if [[ -f build/test-results/test/TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest.xml ]]; then
  cp build/test-results/test/TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest.xml \
    "${PUBLISH_DIR}/${STAMP}-TEST-P3Asn1GatewayProtocolNegativeVectorsTest.xml"
  ARTIFACTS+=("${STAMP}-TEST-P3Asn1GatewayProtocolNegativeVectorsTest.xml")
fi

if [[ -f build/test-results/test/TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest.xml ]]; then
  cp build/test-results/test/TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest.xml \
    "${PUBLISH_DIR}/${STAMP}-TEST-P3Asn1GatewayProtocolTest.xml"
  ARTIFACTS+=("${STAMP}-TEST-P3Asn1GatewayProtocolTest.xml")
fi

if [[ -f build/test-results/test/TEST-it.amhs.service.CotpConnectionTpduTest.xml ]]; then
  cp build/test-results/test/TEST-it.amhs.service.CotpConnectionTpduTest.xml \
    "${PUBLISH_DIR}/${STAMP}-TEST-CotpConnectionTpduTest.xml"
  ARTIFACTS+=("${STAMP}-TEST-CotpConnectionTpduTest.xml")
fi

if [[ -f build/test-results/test/TEST-it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseDiagnosticsTest.xml ]]; then
  cp build/test-results/test/TEST-it.amhs.service.protocol.rfc1006.RFC1006ServiceAcseDiagnosticsTest.xml \
    "${PUBLISH_DIR}/${STAMP}-TEST-RFC1006ServiceAcseDiagnosticsTest.xml"
  ARTIFACTS+=("${STAMP}-TEST-RFC1006ServiceAcseDiagnosticsTest.xml")
fi

{
  echo "release=${RELEASE_ID}"
  echo "timestamp=${STAMP}"
  echo "exit_code=${RESULT}"
  echo "source_log=${LOG_FILE}"
  echo "copied_artifacts="
  for artifact in "${ARTIFACTS[@]}"; do
    echo "  - ${artifact}"
  done
  (cd "$PUBLISH_DIR" && sha256sum "${ARTIFACTS[@]}")
} > "${PUBLISH_DIR}/${STAMP}-manifest.txt"

cp "${PUBLISH_DIR}/${STAMP}-manifest.txt" "${PUBLISH_DIR}/latest-manifest.txt"

echo
cat "${PUBLISH_DIR}/${STAMP}-manifest.txt"
echo
echo "Published release artifacts under: ${PUBLISH_DIR}"

if [[ "$RESULT" -ne 0 ]]; then
  exit "$RESULT"
fi
