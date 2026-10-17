# Command-line options

```
python3 src/astro_scan.py --target ORIGIN [options]
```

Options that take a path accept it with or without a leading `/`; repeated slashes
are collapsed. Repeatable options are marked *(repeatable)*.

## General

| Option | Default | Description |
|---|---|---|
| `--target ORIGIN` | *required* | Target origin, e.g. `https://example.com`. Repeatable. Path, query and default ports are rejected/dropped; use `--base-path`/`--protected-path` for application paths. |
| `--target-file PATH` | — | File with one target origin per line; `#` comments allowed. |
| `--scope ORIGIN` | — | Authorized origin *(repeatable)*. If given, every normalized target must equal one of them exactly. Mandatory for non-loopback targets. |
| `--scope-file PATH` | — | File with one authorized origin per line; `#` comments allowed. |
| `--allow-remote` | off | Acknowledges that non-loopback targets are in scope. Mandatory for non-loopback targets. |
| `--authorization-statement TEXT` | — | Traceable authorization (program, ticket, engagement). At least 12 characters. `@file` reads the statement from a file. Mandatory for non-loopback targets; stored in the report. |
| `--profile {safe,standard,full}` | — | Module preset. `safe` = fingerprint + sourcemaps; `standard` = all non-destructive checks; `full` = all modules. Missing inputs are skipped with a reason. |
| `--modules LIST` | `fingerprint` | Comma-separated module names, `all`, or `all-safe`. Overrides `--profile`. Explicitly named modules fail fast when their mandatory inputs are missing; `all`/`all-safe` skip them with a reason. |
| `--dry-run` | off | Print the resolved plan (targets, scopes, modules, skipped modules, network configuration) and exit without sending requests. |
| `--list-modules` | off | Print every module with its required inputs and the available profiles. |
| `--version` | off | Print the scanner version and exit. |
| `--config PATH` | — | TOML file with defaults for any option below (underscored keys, optional `[astroscan]` table). CLI flags override config values. |
| `--output PATH` | — | Write the JSON evidence bundle here (parent directories are created). Single target only. |
| `--output-dir DIR` | — | Write one JSON bundle per target (`<host>-<port>.json`), `summary.json` for multiple targets, and `astroscan.sarif` when `--format sarif`. |
| `--format {human,json,jsonl,sarif}` | `human` | Terminal output. `json` prints the report, `jsonl` one finding per line, `sarif` a SARIF 2.1.0 document. |
| `--timeout SECONDS` | `8.0` | Per-request timeout. Must be positive. |
| `--delay SECONDS` | `0.25` | Minimum pause between requests. Must not be negative. Raise it to meet program rate limits. |
| `--rate-limit RPS` | `0` | Maximum requests per second (`0` = disabled). The effective interval is `max(--delay, 1/RPS)`. |
| `--max-requests N` | `0` | Global request budget (`0` = unlimited). Exceeding it marks remaining requests as budget-exceeded and makes affected findings `inconclusive`. |
| `--max-retries N` | `1` | Retries for transport errors and `429/500/502/503/504`. |
| `--retry-backoff SECONDS` | `1.0` | Base for exponential retry backoff; `Retry-After` is honoured. |
| `--follow-redirects` / `--no-follow-redirects` | on | Follow redirects whose destination is the target origin or an authorized scope origin. |
| `--max-redirects N` | `5` | Maximum redirect hops. |
| `--fail-on-finding` | off | Exit `1` when the overall status is `vulnerable`. |
| `--fail-on-transport-error` | off | Exit `2` if any HTTP transaction failed at the transport layer. |
| `--fail-on-inconclusive` | off | Exit `2` when the overall status is `inconclusive`. |
| `--quiet` | off | Suppress the full human report; print one summary line per target to stderr. |
| `--verbose` | off | Print every HTTP transaction to stderr. |
| `--user-agent TEXT` | `AstroScan/1.1.0 (authorized-security-test)` | `User-Agent` for every request. Some programs require a specific header value. |

## Network and request headers

| Option | Default | Description |
|---|---|---|
| `--proxy URL` | — | HTTP(S) proxy, e.g. `http://127.0.0.1:8080`. Proxy credentials in the URL are sent as `Proxy-Authorization`. HTTPS targets are tunnelled with `CONNECT`. |
| `--insecure` / `--no-insecure` | off | Disable TLS certificate verification. |
| `--cacert PATH` | — | Custom CA bundle for TLS verification. |
| `--resolve HOST:PORT:ADDRESS` | — | Connect to `ADDRESS` while using `HOST:PORT` for the URL/Host/SNI. Repeatable. IPv6 hosts use `[::1]:443:127.0.0.1`. Ignored when `--proxy` is used. |
| `--header 'Name: value'` | — | Extra header on every request *(repeatable)*. Names are listed (not values) in `configuration.extra_headers`. |
| `--header-file PATH` | — | File with `Name: value` headers; `#` comments allowed. |
| `--cookie 'name=value'` | — | Cookie value *(repeatable)*; joined with `; `. |
| `--cookie-file PATH` | — | File with cookie `name=value` lines. |
| `--bearer TOKEN` | — | Send `Authorization: Bearer TOKEN` unless an explicit `Authorization` header is supplied. |
| `--include-sensitive-request-headers` | off | Store `Authorization`/`Cookie`/API-key values in the evidence bundle. Off by default; they are shown as `<redacted>`. |

## Version fingerprint

| Option | Default | Description |
|---|---|---|
| `--version-path PATH` | — | Extra version-bearing path or same-scope absolute URL *(repeatable)*. Absolute URLs outside the target/scope are rejected. |
| `--max-version-artifact-requests N` | `8` | Cap on artifact and source-map requests made by the fingerprint. |
| `--version-probe-default-artifacts` / `--no-version-probe-default-artifacts` | on | Probe `/package.json`, `/package-lock.json`, `/pnpm-lock.yaml`, `/yarn.lock`. |

## Authorization bypass (`base-bypass`, `encoded-path`)

| Option | Default | Description |
|---|---|---|
| `--base-path PATH` | `/app` | Astro `base`. Must not be `/`. |
| `--protected-path PATH` | `/admin` | Route guarded by middleware. |
| `--marker TEXT` | — | String that only appears in the protected response. **Required** by both modules. |
| `--base-bypass-suffix TEXT` | `X` | Appended to the base without a `/` (`/app` → `/appX`). |
| `--single-encoding-depth N` | `1` | Encoding depth for CVE-2025-64765. |
| `--deep-encoding-depth N` | `12` | Decode passes for CVE-2026-59731 (12 = advisory payload). |

## Source maps

| Option | Default | Description |
|---|---|---|
| `--sourcemap-path PATH` | — | Extra `.map` path or same-scope absolute URL to try first *(repeatable)*; also used by the fingerprint. |
| `--max-sourcemap-requests N` | `20` | Cap on candidate map requests. |
| `--max-source-map-findings N` | `3` | Stop after this many valid maps. |

## Server islands

| Option | Default | Description |
|---|---|---|
| `--server-island-path PATH` | `/` | Page that renders both islands (`server-island-replay`). |
| `--server-island-param NAME` | `shared` | Query parameter that feeds the source island prop. |
| `--server-island-source-name NAME` | `ComponentA` | Island whose encrypted prop is replayed. |
| `--server-island-target-name NAME` | `ComponentB` | Island that receives it as slots. |
| `--server-island-reflected-name NAME` | `ComponentA` | Island used by `server-island-reflected-xss`. |
| `--server-island-reflected-slot NAME` | `astro-scan` | Slot key used by `server-island-reflected-xss`. |

## Reflected XSS

| Option | Default | Module |
|---|---|---|
| `--transition-path`, `--transition-param` | `/`, `duration` | `transition-xss` |
| `--transition-directive-path`, `--transition-directive-param` | `/`, `persist` | `transition-directive-xss` |
| `--spread-attrs-path`, `--spread-attrs-param` | `/`, `props` | `spread-attrs-xss` |
| `--custom-element-path`, `--custom-element-param` | `/`, `props` | `custom-element-xss` |
| `--slot-path`, `--slot-param` | `/`, `tab` | `slot-xss` |
| `--define-vars-path`, `--define-vars-param` | `/`, `name` | `define-vars-xss` |
| `--trailing-slash-mode {never,always}` | `never` | `dev-error-xss` (`never` appends a trailing `/` to the payload path) |
| `--allow-dev-server-check` | off | **Required** for `dev-error-xss`; confirms an exposed development server is in scope. |

## astro/hono CSRF

| Option | Default | Description |
|---|---|---|
| `--hono-csrf-path PATH` | `/api/delete` | Harmless state-changing endpoint. |
| `--hono-csrf-method` | `POST` | One of `POST`, `PUT`, `PATCH`, `DELETE`. |
| `--hono-csrf-origin URL` | `http://astro-scan-cross-origin.invalid` | Mismatched `Origin` header. |
| `--hono-csrf-content-type TYPE` | `application/x-www-form-urlencoded` | Form-like content type. |
| `--hono-csrf-body TEXT` | `astro-scan-csrf-proof=1` | Request body. |
| `--hono-csrf-marker TEXT` | — | **Required.** Response marker proving the handler ran. |
| `--allow-state-changing-check` | off | **Required.** Explicit opt-in to a state-changing request. |

## remotePatterns bypass

| Option | Default | Description |
|---|---|---|
| `--remote-pattern-path PATH` | `/_image` | Image endpoint. |
| `--remote-pattern-allowed-href URL` | — | **Required.** URL inside the allowed pattern, on your host. |
| `--remote-pattern-bypass-href URL` | — | **Required.** URL outside the pattern prefix, on your host. |
| `--remote-pattern-marker TEXT` | — | **Required.** Content both URLs serve. |
| `--i-control-remote-host` | off | **Required.** Confirms both URLs are yours. |

A positive requires both responses to be image content containing the marker; a
marker reflected in an HTML error page is reported as `inconclusive`.

## Controlled-callback SSRF

| Option | Default | Description |
|---|---|---|
| `--callback-listen HOST:PORT` | — | Start the built-in listener (`127.0.0.1:0` = random port). Exclusive with `--callback-url`. |
| `--callback-advertise-host HOST` | — | Address the target should use when listening on `0.0.0.0`. |
| `--callback-url URL` | — | External callback you control. Its path must end in `astro-callback-<token>.svg`. |
| `--i-control-callback` | off | **Required** with either callback option. |
| `--callback-timeout SECONDS` | `5.0` | Wait for the callback per check. |
| `--callback-proof-token TOKEN` | — | Operator-confirmed callback token for an external callback *(repeatable)*. Without it, an external callback cannot produce a `vulnerable` verdict. |
| `--callback-proof-file PATH` | — | File with operator-confirmed callback tokens. |
| `--error-path PATH` | `/astro-scan-nonexistent` | Path that triggers the error page (`host-header-ssrf`). |
| `--image-path PATH` | `/_image` | Image endpoint (`image-proxy-ssrf`). |
| `--image-format FMT` | `svg` | `f=` parameter sent to the image endpoint. |

Explicitly requesting an SSRF module without a callback fails validation. Under a
profile or `--modules all`, the module is skipped with a reason.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (with or without findings, unless a failure flag matched). |
| `1` | `--fail-on-finding` and at least one `vulnerable` finding. |
| `2` | Refused or failed: missing authorization gates, out-of-scope target, missing explicit module inputs, invalid option, local I/O error, or a failure flag matched. The reason is printed to stderr as `astro_scan: …`. |

Network errors on individual requests do **not** abort the scan; they are recorded
as transactions with an `error` field and the affected findings become
`inconclusive`.
