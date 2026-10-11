# Command-line options

```
python3 src/astro_scan.py --target ORIGIN [options]
```

Options that take a path accept it with or without a leading `/`; repeated slashes
are collapsed. Repeatable options are marked *(repeatable)*.

## General

| Option | Default | Description |
|---|---|---|
| `--target ORIGIN` | *required* | Target origin, e.g. `https://example.com`. Path, query and default ports are dropped; host is lower-cased. |
| `--scope ORIGIN` | — | Authorized origin *(repeatable)*. If given, the normalized target must equal one of them exactly. Mandatory for non-loopback targets. |
| `--allow-remote` | off | Acknowledges that a non-loopback target is in scope. Mandatory for non-loopback targets. |
| `--authorization-statement TEXT` | — | Traceable authorization (program, ticket, engagement). At least 12 characters. Mandatory for non-loopback targets; stored in the report. |
| `--modules LIST` | `fingerprint` | Comma-separated module names, or `all`. See [`MODULES.md`](MODULES.md). |
| `--output PATH` | — | Write the JSON evidence bundle here (parent directories are created). |
| `--format {human,json}` | `human` | Terminal output. `json` prints the full report to stdout and the one-line summary to stderr. |
| `--timeout SECONDS` | `8.0` | Per-request timeout. Must be positive. |
| `--delay SECONDS` | `0.25` | Pause between requests/modules. Must not be negative. Raise it to meet program rate limits. |
| `--fail-on-finding` | off | Exit with `1` when the overall status is `vulnerable` (useful in CI). |
| `--header 'Name: value'` | — | Extra header on every request *(repeatable)*, e.g. a program's mandatory research header. Names are listed (not values) in `configuration.extra_headers`. |
| `--user-agent TEXT` | `AstroScan/1.0 (authorized-security-test)` | `User-Agent` for every request. Some programs require a specific header value. |

## Version fingerprint

| Option | Default | Description |
|---|---|---|
| `--version-path PATH` | — | Extra URL path known to expose a version *(repeatable)*. |
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
| `--sourcemap-path PATH` | — | Extra `.map` path to try first *(repeatable)*; also used by the fingerprint. |
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

## Controlled-callback SSRF

| Option | Default | Description |
|---|---|---|
| `--callback-listen HOST:PORT` | — | Start the built-in listener (`127.0.0.1:0` = random port). Exclusive with `--callback-url`. |
| `--callback-advertise-host HOST` | — | Address the target should use when listening on `0.0.0.0`. |
| `--callback-url URL` | — | External callback you control (`…/astro-callback-<token>.svg`). |
| `--i-control-callback` | off | **Required** with either callback option. |
| `--callback-timeout SECONDS` | `5.0` | Wait for the callback per check. |
| `--error-path PATH` | `/astro-scan-nonexistent` | Path that triggers the error page (`host-header-ssrf`). |
| `--image-path PATH` | `/_image` | Image endpoint (`image-proxy-ssrf`). |
| `--image-format FMT` | `svg` | `f=` parameter sent to the image endpoint. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (with or without findings, unless `--fail-on-finding`). |
| `1` | `--fail-on-finding` and at least one `vulnerable` finding. |
| `2` | Refused or failed: missing authorization gates, out-of-scope target, missing module inputs, invalid option, local I/O error. The reason is printed to stderr as `astro_scan: …`. |

Network errors on individual requests do **not** abort the scan; they are recorded
as transactions with an `error` field.
