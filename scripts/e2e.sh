#!/usr/bin/env bash
# Live check for ghgate v0 (SPEC.md, "Live check"). Run by hand: it needs network and a real PAT.
#
#   GHGATE_CONFIG=ghgate.json            config of the running proxy (used to print its CA)
#   GHGATE_CLIENT_TOKEN=<client token>   a client token from that config
#   REAL_PAT_FILE=/path/to/pat           the same PAT the proxy uses, to read core.used directly
#   PRIVATE_REPO=owner/name              a private repo the PAT can read
#   GHGATE_PROXY_ADDR=127.0.0.1:8899     optional
set -euo pipefail

: "${GHGATE_CONFIG:?}" "${GHGATE_CLIENT_TOKEN:?}" "${REAL_PAT_FILE:?}" "${PRIVATE_REPO:?}"
proxy="http://x:${GHGATE_CLIENT_TOKEN}@${GHGATE_PROXY_ADDR:-127.0.0.1:8899}" # CONNECT needs the token as Proxy-Authorization
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

ghgate ca --config "$GHGATE_CONFIG" > "$work/ghgate-ca.pem"
sys_bundle="${SYSTEM_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
cat "$sys_bundle" "$work/ghgate-ca.pem" > "$work/bundle.pem"

core_used() {
  curl -fsS -H "Authorization: Bearer $(cat "$REAL_PAT_FILE")" https://api.github.com/rate_limit | jq .resources.core.used
}

via_gate() {
  GH_TOKEN="$GHGATE_CLIENT_TOKEN" HTTPS_PROXY="$proxy" SSL_CERT_FILE="$work/bundle.pem" "$@"
}

echo "1/3 gh api through ghgate, twice"
via_gate gh api repos/cli/cli --include > "$work/first.txt"
grep -qi '^x-ghgate-cache: miss' "$work/first.txt" || { echo "FAIL: first call was not a miss"; head -20 "$work/first.txt"; exit 1; }
before="$(core_used)"
via_gate gh api repos/cli/cli --include > "$work/second.txt"
grep -qi '^x-ghgate-cache: revalidated' "$work/second.txt" || { echo "FAIL: second call was not revalidated"; head -20 "$work/second.txt"; exit 1; }
after="$(core_used)"
# core_used itself costs one call, so the second gh call must add nothing beyond that.
echo "core.used before=$before after=$after (the rate_limit read in between is not counted)"
[ "$after" -le "$before" ] || { echo "FAIL: core.used moved on the revalidated call"; exit 1; }

echo "2/3 git ls-remote of a private repo through ghgate"
git -c "http.https://github.com/.proxy=$proxy" -c "http.https://github.com/.sslCAInfo=$work/bundle.pem" \
  -c "credential.helper=" -c "http.extraHeader=Authorization: Bearer $GHGATE_CLIENT_TOKEN" \
  ls-remote "https://github.com/$PRIVATE_REPO.git" HEAD

echo "3/3 stats"
curl -fsS http://127.0.0.1:8898/stats | jq .

echo "OK"
