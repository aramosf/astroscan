# AstroScan

AstroScan is an evidence-oriented, WPScan-style checker for selected high-impact
vulnerabilities in the [Astro](https://github.com/withastro/astro) web framework.
It is written for **authorized** security testing (bug bounty programs, pentest
engagements, your own deployments) and produces a JSON evidence bundle that can
be attached to a report.

Two design principles drive the tool:

1. **A fingerprint is not a vulnerability.** AstroScan reports an Astro version
   only when an exact semantic version is exposed by the target, and a version
   match is presented as an *upgrade candidate*, never as exploitability.
2. **A positive needs discriminating evidence.** Every module defines what a
   positive looks like (an auth-gated baseline plus a protected-content marker,
   an inert HTML marker inserted raw, a callback to a host you control…). Anything
   short of that is reported as `not-vulnerable-or-not-applicable` or
   `inconclusive`.

- Single file, **Python standard library only** — no `pip install`.
- Hard authorization gates for any non-loopback target.
- Safe payloads: XSS checks insert an inert custom element, SSRF checks only use
  a callback you control, the memory-corruption input for the AVIF/libheif issue
  is never sent.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Modules](#modules)
- [Output](#output)
- [Repository layout](#repository-layout)
- [Further documentation](#further-documentation)
- [Legal and ethical use](#legal-and-ethical-use)

## Requirements

- Python **3.11** or newer (uses `datetime.UTC`).
- Network reachability to the target and, for the SSRF modules, a callback host
  that the target can reach and that you control.

## Quick start

Help, version and module list:

```bash
python3 src/astro_scan.py --help
python3 src/astro_scan.py --version
python3 src/astro_scan.py --list-modules
```

Version fingerprint plus advisory assessment against a local fixture (loopback
targets need no authorization flags):

```bash
python3 src/astro_scan.py --target http://127.0.0.1:4321 --modules fingerprint
```

The same against an authorized remote target. All three gates are mandatory and
the target must be listed **exactly** in `--scope` (or `--scope-file`):

```bash
python3 src/astro_scan.py \
  --target https://app.example.com \
  --scope https://app.example.com \
  --allow-remote \
  --authorization-statement 'Example program, ticket 123: Astro checks approved' \
  --profile standard \
  --dry-run
```

Remove `--dry-run` to execute. `--dry-run` prints the resolved target(s), scope,
profile, modules, skipped modules and their reasons, request budget and network
configuration without sending a request.

### Pentest workflow

- **Profiles:** `--profile safe` runs fingerprint and source maps; `standard`
  adds every non-destructive check; `full` adds `dev-error-xss` and `hono-csrf`.
  Modules whose mandatory inputs are missing are **skipped with a reason** under
  a profile or `--modules all`, instead of aborting the run. Explicitly naming a
  module (`--modules base-bypass`) still fails fast when its inputs are missing.
- **Scope and targets:** `--scope-file` and `--target-file` accept one exact
  origin per line (`#` comments allowed). `--target` is repeatable and
  `--output-dir` writes one evidence file per target plus `summary.json`.
- **Authorized network paths:** `--proxy`, `--insecure`/`--cacert`, `--cookie`,
  `--cookie-file`, `--bearer`, `--header-file` and `--resolve` cover Burp/ZAP,
  self-signed certificates, authenticated engagements and split-DNS targets.
- **Pacing:** `--delay` is a minimum interval between requests; `--rate-limit`
  caps requests per second; `--max-retries` (default 1) retries transport errors
  and `429/500/502/503/504` with exponential backoff and `Retry-After`;
  `--max-requests` is a global budget.
- **Redirects:** same-origin and in-scope redirects are followed by default
  (`--no-follow-redirects` disables this). Redirects outside the authorized
  origin/scope are recorded and not followed.
- **Output:** `--format human|json|jsonl|sarif`, plus `--output PATH` (single
  target) or `--output-dir DIR` (one JSON bundle per target). `--output` always
  writes the canonical JSON evidence bundle regardless of the terminal format.
- **Failure semantics:** transport errors produce `inconclusive` findings, not
  false negatives. `--fail-on-transport-error` and `--fail-on-inconclusive`
  turn those into exit code `2`; `--fail-on-finding` keeps exit code `1`.

Authorization-bypass check (`/app/admin` versus `/appX/admin`), positive only if
the baseline is `401/403` and the bypass returns your marker:

```bash
python3 src/astro_scan.py \
  --target https://app.example.com --scope https://app.example.com \
  --allow-remote --authorization-statement 'Example program, ticket 123' \
  --modules base-bypass,encoded-path \
  --base-path /app --protected-path /admin --marker ADMIN_SECRET \
  --output evidence/app-example-com-bypass.json
```

Every run starts with a version preflight, so even a single non-fingerprint
module prints the detected version and the number of matching advisories first.

## Modules

| Module | Advisory | Fixed in | Positive requires |
|---|---|---|---|
| `fingerprint` | — | — | Exact version from generator meta, header, package/lock file or source map |
| `base-bypass` | CVE-2026-84376 / GHSA-376h-93r7-7g6f | 7.2.4 | `401/403` baseline + marker on `<base>X<path>` |
| `encoded-path` | CVE-2025-64765, CVE-2025-66202, CVE-2026-59731 | 5.15.8 / 5.15.8 / 6.4.8 | `401/403` baseline + marker on encoded path |
| `transition-xss` | CVE-2026-73422 / GHSA-4g3v-8h47-v7g6 | 7.1.0 | Inert marker inserted raw |
| `transition-directive-xss` | CVE-2026-59727 / GHSA-7pw4-f3q4-r2p2 | 7.0.4 | Inert marker inserted raw |
| `spread-attrs-xss` | CVE-2026-54298 / GHSA-jrpj-wcv7-9fh9 | 6.4.6 | Inert marker inserted raw |
| `custom-element-xss` | CVE-2026-59729 / GHSA-f48w-9m4c-m7f5 | 7.0.6 | Inert marker inserted raw |
| `slot-xss` | CVE-2026-50146 / GHSA-8hv8-536x-4wqp | 6.3.3 | Inert marker inserted raw |
| `define-vars-xss` | CVE-2026-41067 / GHSA-j687-52p2-xcff | 6.1.6 | Inert marker inserted raw |
| `dev-error-xss` | CVE-2025-64745 / GHSA-w2vj-39qv-7vh7 | 5.15.6 | Inert marker inserted raw (dev server; requires `--allow-dev-server-check`) |
| `server-island-reflected-xss` | CVE-2025-64764 / GHSA-wrwg-2hg8-v723 | 5.15.8 | Inert marker inserted raw |
| `server-island-replay` | CVE-2026-45028 / GHSA-xr5h-phrj-8vxv | 6.1.10 | Replayed ciphertext renders marker raw |
| `hono-csrf` | CVE-2026-73423 / GHSA-8mv7-9c27-98vc | 7.0.6 | `200` + your harmless state-change marker |
| `remote-pattern-bypass` | CVE-2026-33769 / GHSA-g735-7g2w-hh3f | 5.18.1 | Allowed control and bypass both return your marker in an image response |
| `sourcemaps` | CVE-2024-56159 / GHSA-49w6-73cw-chjr | 5.0.8 | Valid source map (`version` + `sources`) served |
| `host-header-ssrf` | CVE-2026-54299 / GHSA-2pvr-wf23-7pc7 | 6.4.6 | Verified callback **and** callback token reflected |
| `image-proxy-ssrf` | CVE-2025-59837 / GHSA-qcpr-679q-rhm2 | 5.13.10 | Verified callback (token reflection alone is `inconclusive`) |

`--modules all` runs everything; modules whose mandatory inputs are missing are
skipped with a reason (use `--dry-run` to see the plan first). Every module is
validated against a vulnerable/fixed pair of Docker fixtures in `lab/`
([`docs/LAB.md`](docs/LAB.md)). Detail per module — payloads, options and
limits — in [`docs/MODULES.md`](docs/MODULES.md).

## Output

- **Terminal:** human-readable report by default; `--format json` prints the full
  JSON report to stdout, `jsonl` prints one finding per line, and `sarif` prints
  a SARIF 2.1.0 document. `--quiet` suppresses the full human report.
- **Evidence file:** `--output PATH` always writes the canonical JSON bundle
  (schema `astro-scan-evidence/1`): authorization context, configuration,
  detected versions, version assessment, per-module findings, skipped modules and
  every HTTP transaction (with `Set-Cookie`/auth headers redacted and bodies
  hashed). `--output-dir DIR` writes one file per target plus a summary.
- **Exit codes:** `0` completed, `1` a `vulnerable` finding exists and
  `--fail-on-finding` was given, `2` argument/authorization/network error (or
  `--fail-on-transport-error` / `--fail-on-inconclusive` matched).

Format reference: [`docs/REPORT-FORMAT.md`](docs/REPORT-FORMAT.md).

## Repository layout

```
.
├─ src/astro_scan.py        # the scanner (single file, stdlib only)
├─ tests/test_astro_scan.py # unit tests (no external network)
├─ advisories/              # OSV/GHSA records used for version assessment
├─ lab/                     # Docker vulnerable/fixed fixtures and regression suites
├─ pyproject.toml           # installable console script (`astroscan`)
├─ astroscan.example.toml   # config-file example
├─ LICENSE                  # MIT
├─ .github/workflows/       # unit tests on Python 3.11–3.14
└─ docs/
   ├─ MODULES.md            # per-module reference
   ├─ OPTIONS.md            # full CLI reference with defaults
   ├─ REPORT-FORMAT.md      # JSON evidence schema and statuses
   ├─ SAFETY.md             # authorization gates and safety model
   ├─ LAB.md                # laboratories and regression suites
   └─ DEVELOPMENT.md        # tests, refreshing advisories, adding a module
```

Install as a console script if desired:

```bash
python3 -m pip install .
astroscan --version
```

The scanner locates `advisories/` relative to its own location
(`src/../advisories`), so keep the two directories side by side. The installed
`astroscan` console script expects the `advisories/` directory to be available in
the same layout; running from the repository is the supported deployment.

## Further documentation

- [Module reference](docs/MODULES.md)
- [Command-line options](docs/OPTIONS.md)
- [Evidence report format](docs/REPORT-FORMAT.md)
- [Safety model](docs/SAFETY.md)
- [Laboratories](docs/LAB.md)
- [Development](docs/DEVELOPMENT.md)

## Legal and ethical use

Only scan systems you own or are explicitly authorized to test, within the
program's scope, rules and rate limits. The authorization flags are an audit
trail, not a permission: supplying them does not make a test legal. Several
modules (`hono-csrf`, the SSRF modules, `dev-error-xss`) carry extra
preconditions described in [`docs/SAFETY.md`](docs/SAFETY.md).
