#!/usr/bin/env bash
# Run a list of conformance tests one at a time against the local cluster,
# printing PASS/FAIL per test. Fast timeouts so failures don't hang.
#
# Usage: hack/run-tests.sh Test1 Test2 ...   (or no args = a default core set)
set -u

cd "$(dirname "$0")/../gateway-api" || exit 1
export KUBECONFIG="${KUBECONFIG:-$(cd .. && pwd)/kubeconfig}"

OVERRIDES="GatewayMustHaveAddress:20;GatewayMustHaveCondition:15;GatewayStatusMustHaveListeners:15;GatewayListenersMustHaveConditions:15;HTTPRouteMustNotHaveParents:15;HTTPRouteMustHaveCondition:15;MaxTimeToConsistency:30;DefaultTestTimeout:90;NamespacesMustBeReady:240"

TESTS=("$@")
if [ ${#TESTS[@]} -eq 0 ]; then
  TESTS=(
    HTTPRouteSimpleSameNamespace
    HTTPRouteMatching
    HTTPRouteExactPathMatching
    HTTPRouteHeaderMatching
    HTTPRouteMethodMatching
    HTTPRouteQueryParamMatching
    HTTPRoutePathMatchOrder
    HTTPRouteMatchingAcrossRoutes
    HTTPRouteWeight
    HTTPRouteCrossNamespace
    HTTPRouteObservedGenerationBump
  )
fi

pass=0; fail=0
for t in "${TESTS[@]}"; do
  out=$(go test ./conformance -run TestConformance -timeout 300s -args \
    --gateway-class=gateway-conformance \
    --supported-features=Gateway,HTTPRoute,ReferenceGrant \
    --allow-crds-mismatch \
    --cleanup-base-resources=false \
    --run-test="$t" \
    --timeout-config-overrides="$OVERRIDES" 2>&1)
  if echo "$out" | grep -qE '^ok\s'; then
    echo "PASS  $t"; pass=$((pass+1))
  else
    echo "FAIL  $t"; fail=$((fail+1))
    # Show the first meaningful failure line for context (the line after the
    # generic "Received unexpected error:" wrapper carries the real reason).
    echo "$out" | grep -E 'expected .* to be|not ready yet|does not exist|connection refused|got status|Pod|Namespace|Messages:|timeout while waiting' | head -3 | sed 's/^/        /'
  fi
done
echo "----- $pass passed, $fail failed -----"
