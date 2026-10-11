#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$ROOT/src/astro_scan.py"
EVIDENCE="$ROOT/evidence/priority-matrix"
NETWORK=astro-priority-matrix
CONTAINERS=()

cleanup() {
  if ((${#CONTAINERS[@]})); then
    docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
  fi
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_container() {
  local name=$1 image=$2 port=$3
  docker rm -f "$name" >/dev/null 2>&1 || true
  sleep 0.5
  docker run -d --name "$name" --network "$NETWORK" -p "127.0.0.1:${port}:4321" "$image" >/dev/null
  CONTAINERS+=("$name")
  for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  docker logs "$name" >&2
  return 1
}

remove_container() {
  docker rm -f "$1" >/dev/null 2>&1 || true
}

scan() {
  local port=$1 module=$2 output=$3
  shift 3
  python3 "$SCAN" \
    --target "http://127.0.0.1:${port}" \
    --modules "$module" \
    --output "$EVIDENCE/$output" \
    "$@" >"/tmp/astro-scan-${output}.log"
}

assert_vulnerable() {
  jq -e '.overall_status == "vulnerable" and any(.findings[]; .status == "vulnerable" and .confidence == "high")' "$1" >/dev/null
}

assert_fixed() {
  jq -e '.overall_status == "no-confirmed-finding"' "$1" >/dev/null
}

mkdir -p "$EVIDENCE"
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null

docker build -q -t astro-callback:lab "$ROOT/lab/callback" >/dev/null
docker build -q -t astro-remote-pattern-server:fixture -f "$ROOT/lab/remote-patterns-app/remote.Dockerfile" "$ROOT/lab/remote-patterns-app" >/dev/null
docker build -q -t astro-transition-directive-7.0.3:fixture --build-arg ASTRO_VERSION=7.0.3 "$ROOT/lab/transition-directive-app" >/dev/null
docker build -q -t astro-transition-directive-7.0.4:fixture --build-arg ASTRO_VERSION=7.0.4 "$ROOT/lab/transition-directive-app" >/dev/null
docker build -q -t astro-spread-attrs-6.4.5:fixture --build-arg ASTRO_VERSION=6.4.5 "$ROOT/lab/spread-attrs-app" >/dev/null
docker build -q -t astro-spread-attrs-6.4.6:fixture --build-arg ASTRO_VERSION=6.4.6 "$ROOT/lab/spread-attrs-app" >/dev/null
docker build -q -t astro-custom-element-7.0.5:fixture --build-arg ASTRO_VERSION=7.0.5 "$ROOT/lab/custom-element-app" >/dev/null
docker build -q -t astro-custom-element-7.0.6:fixture --build-arg ASTRO_VERSION=7.0.6 "$ROOT/lab/custom-element-app" >/dev/null
docker build -q -t astro-hono-origin-7.0.5:fixture --build-arg ASTRO_VERSION=7.0.5 "$ROOT/lab/hono-origin-app" >/dev/null
docker build -q -t astro-hono-origin-7.0.6:fixture --build-arg ASTRO_VERSION=7.0.6 "$ROOT/lab/hono-origin-app" >/dev/null
docker build -q -t astro-remote-patterns-5.18.0:fixture --build-arg ASTRO_VERSION=5.18.0 "$ROOT/lab/remote-patterns-app" >/dev/null
docker build -q -t astro-remote-patterns-5.18.1:fixture --build-arg ASTRO_VERSION=5.18.1 "$ROOT/lab/remote-patterns-app" >/dev/null
docker build -q -t astro-deep-encoded-6.4.7:fixture --build-arg ASTRO_VERSION=6.4.7 "$ROOT/lab/deep-encoded-app" >/dev/null
docker build -q -t astro-deep-encoded-6.4.8:fixture --build-arg ASTRO_VERSION=6.4.8 "$ROOT/lab/deep-encoded-app" >/dev/null
docker build -q -t astro-host-header-6.4.5:fixture --build-arg ASTRO_VERSION=6.4.5 "$ROOT/lab/host-header-app" >/dev/null
docker build -q -t astro-host-header-6.4.6:fixture --build-arg ASTRO_VERSION=6.4.6 "$ROOT/lab/host-header-app" >/dev/null
docker build -q -t astro-server-island-6.1.9:fixture --build-arg ASTRO_VERSION=6.1.9 "$ROOT/lab/server-island-app" >/dev/null
docker build -q -t astro-server-island-6.1.10:fixture --build-arg ASTRO_VERSION=6.1.10 "$ROOT/lab/server-island-app" >/dev/null
docker build -q -t astro-server-island-reflected-5.15.7:fixture --build-arg ASTRO_VERSION=5.15.7 --build-arg NODE_ADAPTER_VERSION=9.4.5 "$ROOT/lab/server-island-app" >/dev/null
docker build -q -t astro-server-island-reflected-5.15.8:fixture --build-arg ASTRO_VERSION=5.15.8 --build-arg NODE_ADAPTER_VERSION=9.4.5 "$ROOT/lab/server-island-app" >/dev/null
docker build -q -t astro-sourcemap-5.0.6:fixture --build-arg ASTRO_VERSION=5.0.6 "$ROOT/lab/sourcemap-app" >/dev/null
docker build -q -t astro-sourcemap-5.0.7:fixture --build-arg ASTRO_VERSION=5.0.7 "$ROOT/lab/sourcemap-app" >/dev/null
docker build -q -t astro-cloudflare-image-vulnerable:fixture --build-arg ASTRO_VERSION=5.13.4 --build-arg CLOUDFLARE_ADAPTER_VERSION=12.6.8 "$ROOT/lab/cloudflare-image-app" >/dev/null
docker build -q -t astro-cloudflare-image-fixed:fixture --build-arg ASTRO_VERSION=5.13.10 --build-arg CLOUDFLARE_ADAPTER_VERSION=12.6.10 "$ROOT/lab/cloudflare-image-app" >/dev/null

start_container astro-priority-transition-vuln astro-transition-directive-7.0.3:fixture 4340
scan 4340 transition-directive-xss transition-directive-7.0.3.json
assert_vulnerable "$EVIDENCE/transition-directive-7.0.3.json"
remove_container astro-priority-transition-vuln
start_container astro-priority-transition-fixed astro-transition-directive-7.0.4:fixture 4341
scan 4341 transition-directive-xss transition-directive-7.0.4.json
assert_fixed "$EVIDENCE/transition-directive-7.0.4.json"
remove_container astro-priority-transition-fixed

start_container astro-priority-spread-vuln astro-spread-attrs-6.4.5:fixture 4340
scan 4340 spread-attrs-xss spread-attrs-6.4.5.json
assert_vulnerable "$EVIDENCE/spread-attrs-6.4.5.json"
remove_container astro-priority-spread-vuln
start_container astro-priority-spread-fixed astro-spread-attrs-6.4.6:fixture 4341
scan 4341 spread-attrs-xss spread-attrs-6.4.6.json
assert_fixed "$EVIDENCE/spread-attrs-6.4.6.json"
remove_container astro-priority-spread-fixed

start_container astro-priority-custom-vuln astro-custom-element-7.0.5:fixture 4340
scan 4340 custom-element-xss custom-element-7.0.5.json
assert_vulnerable "$EVIDENCE/custom-element-7.0.5.json"
remove_container astro-priority-custom-vuln
start_container astro-priority-custom-fixed astro-custom-element-7.0.6:fixture 4341
scan 4341 custom-element-xss custom-element-7.0.6.json
assert_fixed "$EVIDENCE/custom-element-7.0.6.json"
remove_container astro-priority-custom-fixed

start_container astro-priority-hono-vuln astro-hono-origin-7.0.5:fixture 4340
scan 4340 hono-csrf hono-origin-7.0.5.json --allow-state-changing-check --hono-csrf-path /api/delete --hono-csrf-marker 'mutations":1'
assert_vulnerable "$EVIDENCE/hono-origin-7.0.5.json"
remove_container astro-priority-hono-vuln
start_container astro-priority-hono-fixed astro-hono-origin-7.0.6:fixture 4341
scan 4341 hono-csrf hono-origin-7.0.6.json --allow-state-changing-check --hono-csrf-path /api/delete --hono-csrf-marker 'mutations":1'
assert_fixed "$EVIDENCE/hono-origin-7.0.6.json"
remove_container astro-priority-hono-fixed

docker run -d --name astro-priority-remote-server --network "$NETWORK" --network-alias remote-server astro-remote-pattern-server:fixture >/dev/null
CONTAINERS+=(astro-priority-remote-server)
ready=false
for _ in $(seq 1 40); do
  if docker run --rm --network "$NETWORK" astro-callback:lab python -c "import urllib.request; urllib.request.urlopen('http://remote-server:9999/img/allowed.svg')" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.25
done
$ready || { echo 'remote-pattern server did not become ready' >&2; exit 1; }
start_container astro-priority-remote-vuln astro-remote-patterns-5.18.0:fixture 4340
scan 4340 remote-pattern-bypass remote-patterns-5.18.0.json \
  --remote-pattern-allowed-href http://remote-server:9999/img/allowed.svg \
  --remote-pattern-bypass-href http://remote-server:9999/evil/img/secret.svg \
  --remote-pattern-marker '<astro-scan-remote-patterns>OK</astro-scan-remote-patterns>' \
  --i-control-remote-host
assert_vulnerable "$EVIDENCE/remote-patterns-5.18.0.json"
remove_container astro-priority-remote-vuln
start_container astro-priority-remote-fixed astro-remote-patterns-5.18.1:fixture 4341
scan 4341 remote-pattern-bypass remote-patterns-5.18.1.json \
  --remote-pattern-allowed-href http://remote-server:9999/img/allowed.svg \
  --remote-pattern-bypass-href http://remote-server:9999/evil/img/secret.svg \
  --remote-pattern-marker '<astro-scan-remote-patterns>OK</astro-scan-remote-patterns>' \
  --i-control-remote-host
assert_fixed "$EVIDENCE/remote-patterns-5.18.1.json"
remove_container astro-priority-remote-vuln
remove_container astro-priority-remote-fixed

start_container astro-priority-deep-vuln astro-deep-encoded-6.4.7:fixture 4340
scan 4340 encoded-path deep-encoded-6.4.7.json --protected-path /admin --marker ASTRO_DEEP_ENCODING_ADMIN_SECRET --deep-encoding-depth 12
assert_vulnerable "$EVIDENCE/deep-encoded-6.4.7.json"
remove_container astro-priority-deep-vuln
start_container astro-priority-deep-fixed astro-deep-encoded-6.4.8:fixture 4341
scan 4341 encoded-path deep-encoded-6.4.8.json --protected-path /admin --marker ASTRO_DEEP_ENCODING_ADMIN_SECRET --deep-encoding-depth 12
assert_fixed "$EVIDENCE/deep-encoded-6.4.8.json"
remove_container astro-priority-deep-fixed

callback_token="priority-matrix-$(date +%s)-$RANDOM"
docker run -d --name astro-priority-callback --network "$NETWORK" -e CALLBACK_TOKEN="$callback_token" astro-callback:lab >/dev/null
CONTAINERS+=(astro-priority-callback)
ready=false
for _ in $(seq 1 40); do
  if docker exec astro-priority-callback python -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:9999/404.html').status == 200" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.25
done
$ready || { echo 'callback server did not become ready' >&2; exit 1; }
start_container astro-priority-host-vuln astro-host-header-6.4.5:fixture 4340
scan 4340 fingerprint fingerprint-6.4.5.json --no-version-probe-default-artifacts
scan 4340 host-header-ssrf host-header-6.4.5.json \
  --callback-url "http://astro-priority-callback:9999/astro-callback-${callback_token}.svg" \
  --i-control-callback
assert_vulnerable "$EVIDENCE/host-header-6.4.5.json"
remove_container astro-priority-host-vuln
start_container astro-priority-host-fixed astro-host-header-6.4.6:fixture 4341
scan 4341 fingerprint fingerprint-6.4.6.json --no-version-probe-default-artifacts
scan 4341 host-header-ssrf host-header-6.4.6.json \
  --callback-url "http://astro-priority-callback:9999/astro-callback-${callback_token}.svg" \
  --i-control-callback
assert_fixed "$EVIDENCE/host-header-6.4.6.json"
remove_container astro-priority-host-fixed

start_container astro-priority-island-vuln astro-server-island-6.1.9:fixture 4340
scan 4340 server-island-replay server-island-6.1.9.json
assert_vulnerable "$EVIDENCE/server-island-6.1.9.json"
remove_container astro-priority-island-vuln
start_container astro-priority-island-fixed astro-server-island-6.1.10:fixture 4341
scan 4341 server-island-replay server-island-6.1.10.json
assert_fixed "$EVIDENCE/server-island-6.1.10.json"
remove_container astro-priority-island-fixed

start_container astro-priority-reflected-vuln astro-server-island-reflected-5.15.7:fixture 4340
scan 4340 server-island-reflected-xss server-island-reflected-5.15.7.json
assert_vulnerable "$EVIDENCE/server-island-reflected-5.15.7.json"
remove_container astro-priority-reflected-vuln
start_container astro-priority-reflected-fixed astro-server-island-reflected-5.15.8:fixture 4341
scan 4341 server-island-reflected-xss server-island-reflected-5.15.8.json
assert_fixed "$EVIDENCE/server-island-reflected-5.15.8.json"
remove_container astro-priority-reflected-fixed

start_container astro-priority-sourcemap-vuln astro-sourcemap-5.0.6:fixture 4340
scan 4340 sourcemaps sourcemaps-5.0.6.json
assert_vulnerable "$EVIDENCE/sourcemaps-5.0.6.json"
remove_container astro-priority-sourcemap-vuln
start_container astro-priority-sourcemap-fixed astro-sourcemap-5.0.7:fixture 4341
scan 4341 sourcemaps sourcemaps-5.0.7.json
assert_fixed "$EVIDENCE/sourcemaps-5.0.7.json"
remove_container astro-priority-sourcemap-fixed

start_container astro-priority-image-vuln astro-cloudflare-image-vulnerable:fixture 4340
scan 4340 fingerprint,image-proxy-ssrf cloudflare-image-ssrf-5.13.4.json \
  --image-path /image \
  --callback-url "http://astro-priority-callback:9999/astro-callback-${callback_token}-image-vulnerable.svg" \
  --i-control-callback
assert_vulnerable "$EVIDENCE/cloudflare-image-ssrf-5.13.4.json"
remove_container astro-priority-image-vuln
start_container astro-priority-image-fixed astro-cloudflare-image-fixed:fixture 4341
scan 4341 fingerprint,image-proxy-ssrf cloudflare-image-ssrf-5.13.10.json \
  --image-path /image \
  --callback-url "http://astro-priority-callback:9999/astro-callback-${callback_token}-image-fixed.svg" \
  --i-control-callback
assert_fixed "$EVIDENCE/cloudflare-image-ssrf-5.13.10.json"
remove_container astro-priority-image-fixed

{
  for file in "$EVIDENCE"/*.json; do
    printf '%s\t%s\t%s\n' "$(basename "$file")" "$(jq -r .overall_status "$file")" "$(jq -r '.findings[0].confidence // "none"' "$file")"
  done
} | sort >"$EVIDENCE/REGRESSION-SUMMARY.tsv"
(
  cd "$ROOT/evidence"
  find . -type f ! -name SHA256SUMS.txt -exec sha256sum {} + | sort >SHA256SUMS.txt
)
echo "Priority regression passed: $EVIDENCE/REGRESSION-SUMMARY.tsv"
