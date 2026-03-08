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

mkdir -p build/evidence
LOG_FILE="build/evidence/p3-multi-vendor-evidence.log"

CMD=(
  ./gradlew test
  --tests it.amhs.service.protocol.p3.P3Asn1GatewayProtocolTest
  --tests it.amhs.service.protocol.p3.P3GatewaySessionServiceTest
)

{
  echo "# multi-vendor evidence run"
  date -u +"%Y-%m-%dT%H:%M:%SZ"
  echo "JAVA_HOME=${JAVA_HOME:-unset}"
  echo "command: ${CMD[*]}"
  "${CMD[@]}"
} | tee "$LOG_FILE"

echo
echo "Evidence log: $LOG_FILE"
echo "JUnit XML: build/test-results/test"
echo "HTML report: build/reports/tests/test/index.html"
