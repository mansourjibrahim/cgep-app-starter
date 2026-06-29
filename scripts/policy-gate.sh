#!/usr/bin/env bash
set -euo pipefail
PLAN_JSON="${1:?usage: policy-gate.sh <plan.json>}"
POLICY_DIR="${2:-policies}"
echo "Evaluating HIPAA policy suite against ${PLAN_JSON}..."
DENIES=$(opa eval --data "${POLICY_DIR}" --input "${PLAN_JSON}" \
  "[msg | data.compliance.hipaa[pkg].deny[msg]]" --format raw)
COUNT=$(echo "${DENIES}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
if [ "${COUNT}" -gt 0 ]; then
  echo "POLICY GATE FAILED — ${COUNT} violation(s):"
  echo "${DENIES}" | python3 -c "import sys,json; [print('  X', m) for m in json.load(sys.stdin)]"
  exit 1
else
  echo "POLICY GATE PASSED — 0 violations."
  exit 0
fi
