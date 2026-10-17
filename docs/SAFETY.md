# Safety model

AstroScan is meant to be run inside an authorized engagement. The gates below
make an accidental or out-of-scope run fail **before** the first request, and the
payloads are chosen so that a positive proves the vulnerability without causing
harm.

## Authorization gates

Checked before any network activity; a failure exits with code `2`.

| Gate | Applies to | Rule |
|---|---|---|
| Loopback exemption | `localhost`, `*.localhost`, loopback IPs | No authorization flags needed (local fixtures). |
| `--allow-remote` | every other target | Explicit acknowledgement that the target is in scope. |
| `--scope` / `--scope-file` | every other target | At least one origin; every normalized target must match one **exactly** (scheme, host and port). No wildcards, no subdomain inheritance. |
| `--authorization-statement` | every other target | ≥ 12 characters; `@file` is supported; stored verbatim in the evidence bundle as an audit trail. |
| `--marker` | `base-bypass`, `encoded-path` | Without a protected-content marker a positive would be guesswork. |
| `--allow-state-changing-check` + `--hono-csrf-marker` | `hono-csrf` | The request is state-changing by design. |
| `--allow-dev-server-check` | `dev-error-xss` | The check is only meaningful against an exposed development server. |
| `--i-control-remote-host` + both hrefs + marker | `remote-pattern-bypass` | Both fetched URLs must be yours. |
| `--i-control-callback` | `--callback-url`, `--callback-listen` | SSRF only ever points at a callback you control. |
| `--callback-proof-token` / `--callback-proof-file` | external `--callback-url` | The scanner cannot observe an external callback log; without operator proof the result stays `inconclusive`. |

Gates record intent; they do not grant permission. Read the program rules first.

## Profiles, explicit modules and skips

- Explicitly naming a module (`--modules base-bypass`) still fails before any
  request when its mandatory inputs are missing.
- `--profile safe|standard|full`, `--modules all` and `--modules all-safe` skip
  modules whose inputs are missing and record the reason in `skipped_modules`
  and the human report. This is a usability feature, not a relaxation of the
  authorization gates above.
- `--dry-run` prints the resolved plan, including skips, without network access.

## What is sent, and what is not

- **XSS:** an inert `<astro-scan-xss data-token="…">` element. No script, no
  event handler, no external resource.
- **SSRF:** only the operator-controlled callback URL. No internal ranges,
  cloud-metadata addresses or third-party hosts are ever generated. A
  `vulnerable` verdict requires a verified callback (local listener or explicit
  operator proof); a token merely reflected in the response is `inconclusive`.
- **CSRF:** one request to the endpoint and body you specify.
- **Authorization bypass:** two `GET` requests per check; nothing is modified.
- **Memory corruption:** the crafted HEIC for GHSA-26w7-cxv4-gfx2 is never
  transmitted by the scanner. Its generator (`lab/generate_heic_poc.py`) exists
  only for the local ASan laboratory; see [`LAB.md`](LAB.md).
- **Volume:** a fingerprint-only run makes at most 1 + 8 requests by default; the
  `sourcemaps` module up to 1 + 20. `--delay` (0.25 s), `--rate-limit` and
  `--max-requests` bound the request rate and total volume.
- **Redirects:** only same-origin or explicitly scoped destinations are followed;
  anything else is recorded and not requested.
- **Transport failures:** a timeout or connection error becomes an `inconclusive`
  finding, not a false negative. `--fail-on-transport-error` turns any transport
  error into exit code `2`.

## Evidence hygiene

- Session-bearing response headers are redacted.
- `Authorization`, `Cookie`, `Proxy-Authorization` and API-key request headers are
  redacted by default; use `--include-sensitive-request-headers` only when the
  engagement requires the raw values in the bundle.
- Bodies are hashed; only a 512-character preview and short marker contexts are
  stored.
- Request headers and the authorization statement are stored as given (minus the
  redaction above): never put credentials, tokens or private identifiers in
  options.
- `--modules all` against a real target is rarely right: most modules need a
  known, target-specific sink; pick modules after mapping the application or use
  a profile plus `--dry-run`.

## Interpreting results responsibly

- A version match is an **upgrade candidate**, not a vulnerability.
- `not-vulnerable-or-not-applicable` often means "the vulnerable feature is not
  used here", not "patched".
- `inconclusive` means the check could not decide: transport error, missing
  baseline, failed control, token reflection without callback evidence, or an
  exhausted request budget. It is not a negative result.
- A positive proves the primitive described in the module's *proof boundary*;
  impact beyond that (session theft, internal-network access, data exposure)
  needs separate, explicitly authorized work.
