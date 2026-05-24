#!/usr/bin/env bash
# Penetration test: attempt each attack; expect all to fail.
set -uo pipefail
PASS=0; FAIL=0

check() {
    if eval "$1"; then echo "✗ $2 SUCCEEDED (bad)"; FAIL=$((FAIL+1));
    else echo "✓ $2 BLOCKED (good)"; PASS=$((PASS+1)); fi
}

echo "Test 1: cross-tenant secret read"
check 'kubectl --as=user:team-a:dev get secret -n team-b' \
      "Cross-tenant secret read"

echo "Test 2: deploy unsigned image"
check 'kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: { name: unsigned-test, namespace: iris }
spec: { containers: [{ name: c, image: random/unsigned:latest }] }
EOF' "Unsigned image deploy"

echo "Test 3: spawn shell in ML pod (Falco should alert)"
POD=$(kubectl get pod -n iris -l app=iris-api -o name | head -1)
kubectl exec -n iris $POD -- /bin/sh -c "echo testing" 2>/dev/null
sleep 5
kubectl logs -n falco daemonset/falco | grep "Shell in ML pod" && echo "  Falco detected"

echo "Test 4: lateral movement (team-A pod to team-B service)"
check 'kubectl run -n team-a probe --rm -i --restart=Never --image=curlimages/curl -- curl -m 3 http://service.team-b.svc' \
      "Cross-namespace HTTP"

echo "---"
echo "Passed (blocked): $PASS"
echo "Failed (succeeded): $FAIL"
exit $FAIL
