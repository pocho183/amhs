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
WORK_DIR="build/evidence/releases/${RELEASE_ID}/p3-multi-vendor/${STAMP}"
PUBLISH_DIR="docs/icao/releases/${RELEASE_ID}/evidence/p3-multi-vendor"

mkdir -p "$WORK_DIR" "$PUBLISH_DIR"

LOG_FILE="${WORK_DIR}/run.log"
CMD=(
  ./gradlew test
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest
  --tests it.amhs.service.protocol.p3.P3GatewaySessionServiceTest
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest
)

set +e
{
  echo "# multi-vendor bind/submit/status/report/release evidence run"
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
for suite in \
  TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest.xml \
  TEST-it.amhs.service.protocol.p3.P3GatewaySessionServiceTest.xml \
  TEST-it.amhs.service.protocol.p3.P3Asn1GatewayProtocolNegativeVectorsTest.xml; do
  if [[ -f "build/test-results/test/${suite}" ]]; then
    cp "build/test-results/test/${suite}" "${PUBLISH_DIR}/${STAMP}-${suite}"
    ARTIFACTS+=("${STAMP}-${suite}")
  fi
done

DIAGNOSTIC_SUMMARY="${PUBLISH_DIR}/${STAMP}-diagnostics-summary.txt"
{
  echo "release=${RELEASE_ID}"
  echo "timestamp=${STAMP}"
  echo "diagnostic_samples="
  awk '/ERR code=association detail=Release received before bind/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/ERR code=association detail=Submit received before bind/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/ERR code=association-closed detail=Association already released/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/ERR code=association detail=Bind received on already bound association/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/invalid-operation-role/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/unsupported-operation/ {print "  - "$0}' "$LOG_FILE" | head -n 1
  awk '/RTORJ/ {print "  - "$0}' "$LOG_FILE" | head -n 1
} > "$DIAGNOSTIC_SUMMARY"
ARTIFACTS+=("${STAMP}-diagnostics-summary.txt")

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
cat "$DIAGNOSTIC_SUMMARY"
echo

echo "Published release artifacts under: ${PUBLISH_DIR}"

if [[ "$RESULT" -ne 0 ]]; then
  exit "$RESULT"
fi
