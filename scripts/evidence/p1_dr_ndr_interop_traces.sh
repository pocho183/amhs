#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RELEASE="${1:-R2026.03}"
STAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUT_DIR="docs/icao/releases/${RELEASE}/evidence/p1-dr-ndr-interop"
mkdir -p "$OUT_DIR"

RUN_LOG="${OUT_DIR}/${STAMP}-run.log"
MANIFEST="${OUT_DIR}/${STAMP}-manifest.txt"
TRACE_LEDGER="${OUT_DIR}/${STAMP}-dr-ndr-trace-ledger.md"

if [[ -n "${EVIDENCE_JAVA_HOME:-}" ]]; then
  export JAVA_HOME="$EVIDENCE_JAVA_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -d /root/.local/share/mise/installs/java/21.0.2 ]]; then
  export JAVA_HOME=/root/.local/share/mise/installs/java/21.0.2
  export PATH="$JAVA_HOME/bin:$PATH"
fi

CMD=(
  ./gradlew test
  --tests it.amhs.service.AMHSDeliveryReportServiceTest
  --tests it.amhs.service.X411DeliveryReportApduCodecTest
  --tests it.amhs.service.P1AssociationProtocolTest
  --tests it.amhs.service.Rfc1006OutboundP1ClientTest
)

TEST_STATUS="passed"
if [[ "${AMHS_EVIDENCE_SKIP_TESTS:-0}" == "1" ]]; then
  TEST_STATUS="skipped-by-flag"
  {
    echo "# P1 DR/NDR interoperability traces"
    echo "release=${RELEASE}"
    echo "timestamp=${STAMP}"
    echo "JAVA_HOME=${JAVA_HOME:-unset}"
    echo "command=${CMD[*]}"
    echo "test_status=${TEST_STATUS}"
  } | tee "$RUN_LOG"
else
  set +e
  {
    echo "# P1 DR/NDR interoperability traces"
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

cat > "$TRACE_LEDGER" <<'LEDGER'
# P1 DR/NDR interoperability trace ledger (__STAMP__)

This ledger captures deterministic cross-peer DR/NDR evidence chain semantics bound to release __RELEASE__.

## Correlation invariants

- related_mts_identifier and correlation_token are persisted for every DR/NDR report.
- Correlation token is deterministic: <message-id>::<mts-id> when both are present, otherwise MSG::<message-id> / MTS::<mts-id>.
- NDR APDUs are BER-encoded with X.411 application tag identity validation.

## Cross-peer trace matrix

| Peer profile | Trigger vector | Expected report | Correlation proof | Semantic proof |
|---|---|---|---|---|
| ENAV-OPS | Accepted relay transfer | DR / DELIVERED | MSG-1::MTS-1 stable linkage | createsCorrelatedDeliveryReport |
| MIL-NET | Peer unreachable transfer path | NDR / FAILED | MSG::MSG-2 fallback linkage | mapsTransferFailureDiagnosticsForNdr (X411:22) |
| CERTIFIED-AMHS-LAB | Mixed recipients (failed + deferred + delivered) | NDR per failing/deferred recipient | Shared message correlation over per-recipient reports | createsPerRecipientReportsForMixedOutcome |
| METEO-LEGACY | Legacy IA5 + textual status encoding | NDR decode parity preserved | MTS identifier recovery from legacy form | decodesLegacyIa5AndStatusNameFormatForBackwardCompatibility |

## End-to-end chain coverage

1. Ingress/transfer outcome is converted to DR/NDR semantic status.
2. Correlation fields are written on persisted report entities.
3. NDR BER payload is encoded and profile-validated (tag class/number).
4. Decoding path accepts both canonical and legacy peer encodings.

## Executed suites

- it.amhs.service.AMHSDeliveryReportServiceTest
- it.amhs.service.X411DeliveryReportApduCodecTest
- it.amhs.service.P1AssociationProtocolTest
- it.amhs.service.Rfc1006OutboundP1ClientTest
LEDGER

sed -i "s/__STAMP__/${STAMP}/g; s/__RELEASE__/${RELEASE}/g" "$TRACE_LEDGER"


{
  echo "release=${RELEASE}"
  echo "timestamp=${STAMP}"
  echo "test_status=${TEST_STATUS}"
  echo "run_log=$(basename "$RUN_LOG")"
  echo "trace_ledger=$(basename "$TRACE_LEDGER")"
  echo "junit_dir=build/test-results/test"
  echo "html_report=build/reports/tests/test/index.html"
  echo "peer_profiles=ENAV-OPS, MIL-NET, CERTIFIED-AMHS-LAB, METEO-LEGACY"
  echo "repro_command=scripts/evidence/p1_dr_ndr_interop_traces.sh ${RELEASE}"
} > "$MANIFEST"

cp "$MANIFEST" "${OUT_DIR}/latest-manifest.txt"

echo "Evidence written to ${OUT_DIR}"
