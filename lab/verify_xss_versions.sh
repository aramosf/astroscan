#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ROOT
SCANNER="${ROOT}/src/astro_scan.py"
EVIDENCE="${ROOT}/evidence/xss-matrix"
mkdir -p "${EVIDENCE}"

started_containers=()
cleanup() {
  if [ "${#started_containers[@]}" -gt 0 ]; then docker rm -f "${started_containers[@]}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

scan_fixture() {
  local name="$1" image="$2" port="$3" mode="$4" output="$5"
  shift 5
  local -a command=("docker" "run" "--rm" "-d" "--name" "${name}" "-p" "127.0.0.1:${port}:4321" "${image}")
  if [ "${mode}" = "dev" ]; then
    command+=(npm run dev -- --host 0.0.0.0 --port 4321)
  fi
  "${command[@]}" >/dev/null
  started_containers+=("${name}")

  local ready=0
  for _ in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:${port}/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
  done
  if [ "${ready}" -ne 1 ]; then docker logs "${name}" >&2 || true; return 1; fi

  python3 "${SCANNER}" --target "http://127.0.0.1:${port}" "$@" --output "${output}" >/dev/null
  docker rm -f "${name}" >/dev/null
  started_containers=("${started_containers[@]:1}")
}

scan_fixture astro-scan-xss-631 astro-xss-6.3.1:fixture 4331 dev "${EVIDENCE}/astro-6.3.1.json" \
  --modules transition-xss,slot-xss,define-vars-xss \
  --transition-path /transition --slot-path /slot --define-vars-path /define
scan_fixture astro-scan-xss-633 astro-xss-6.3.3:fixture 4332 dev "${EVIDENCE}/astro-6.3.3.json" \
  --modules transition-xss,slot-xss,define-vars-xss \
  --transition-path /transition --slot-path /slot --define-vars-path /define
scan_fixture astro-scan-xss-615 astro-xss-6.1.5:fixture 4337 dev "${EVIDENCE}/astro-6.1.5.json" \
  --modules define-vars-xss --define-vars-path /define
scan_fixture astro-scan-xss-616 astro-xss-6.1.6:fixture 4338 dev "${EVIDENCE}/astro-6.1.6.json" \
  --modules define-vars-xss --define-vars-path /define
scan_fixture astro-scan-xss-709 astro-xss-7.0.9:fixture 4333 prod "${EVIDENCE}/astro-7.0.9.json" \
  --modules transition-xss --transition-path /transition
scan_fixture astro-scan-xss-710 astro-xss-7.1.0:fixture 4334 prod "${EVIDENCE}/astro-7.1.0.json" \
  --modules transition-xss --transition-path /transition
scan_fixture astro-scan-xss-dev5155 astro-xss-dev-5.15.5:fixture 4335 prod "${EVIDENCE}/astro-dev-5.15.5.json" \
  --modules dev-error-xss --trailing-slash-mode never
scan_fixture astro-scan-xss-dev5156 astro-xss-dev-5.15.6:fixture 4336 prod "${EVIDENCE}/astro-dev-5.15.6.json" \
  --modules dev-error-xss --trailing-slash-mode never

python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['ROOT']) / 'evidence' / 'xss-matrix'
expected = {
    'astro-6.3.1.json': {
        'CVE-2026-73422 / GHSA-4g3v-8h47-v7g6': 'vulnerable',
        'CVE-2026-50146 / GHSA-8hv8-536x-4wqp': 'vulnerable',
        'CVE-2026-41067 / GHSA-j687-52p2-xcff': 'not-vulnerable-or-not-applicable',
    },
    'astro-6.3.3.json': {
        'CVE-2026-73422 / GHSA-4g3v-8h47-v7g6': 'vulnerable',
        'CVE-2026-50146 / GHSA-8hv8-536x-4wqp': 'not-vulnerable-or-not-applicable',
        'CVE-2026-41067 / GHSA-j687-52p2-xcff': 'not-vulnerable-or-not-applicable',
    },
    'astro-6.1.5.json': {'CVE-2026-41067 / GHSA-j687-52p2-xcff': 'vulnerable'},
    'astro-6.1.6.json': {'CVE-2026-41067 / GHSA-j687-52p2-xcff': 'not-vulnerable-or-not-applicable'},
    'astro-7.0.9.json': {'CVE-2026-73422 / GHSA-4g3v-8h47-v7g6': 'vulnerable'},
    'astro-7.1.0.json': {'CVE-2026-73422 / GHSA-4g3v-8h47-v7g6': 'not-vulnerable-or-not-applicable'},
    'astro-dev-5.15.5.json': {'CVE-2025-64745 / GHSA-w2vj-39qv-7vh7': 'vulnerable'},
    'astro-dev-5.15.6.json': {'CVE-2025-64745 / GHSA-w2vj-39qv-7vh7': 'not-vulnerable-or-not-applicable'},
}
for filename, statuses in expected.items():
    report = json.loads((root / filename).read_text())
    actual = {finding['identifier']: finding['status'] for finding in report['findings']}
    for identifier, status in statuses.items():
        assert actual.get(identifier) == status, (filename, identifier, actual.get(identifier), status)
    print(f'{filename}: PASS')
PY
