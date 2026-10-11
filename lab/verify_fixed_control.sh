#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS="${ROOT}/lab/artifacts"
test -s "${ARTIFACTS}/CVE-2026-84383.heic"

echo "[*] Building fixed libheif v1.23.2 control"
docker compose --project-directory "${ROOT}/lab" build libheif-fixed

echo "[*] Decoding the same crafted HEIC with the fixed control"
set +e
docker compose --project-directory "${ROOT}/lab" run --rm \
  -v "${ARTIFACTS}:/artifacts" \
  libheif-fixed /artifacts/CVE-2026-84383.heic /artifacts/fixed-output.png \
  >"${ARTIFACTS}/CVE-2026-84383-fixed.log" 2>&1
status=$?
set -e

cat "${ARTIFACTS}/CVE-2026-84383-fixed.log"
if rg -q "AddressSanitizer" "${ARTIFACTS}/CVE-2026-84383-fixed.log"; then
  echo "[-] Fixed control unexpectedly produced AddressSanitizer output" >&2
  exit 1
fi
echo "[+] Fixed control completed without AddressSanitizer (decoder exit=${status})"
