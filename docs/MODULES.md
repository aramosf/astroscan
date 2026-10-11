# Module reference

Each module maps to one or more public Astro advisories. For every module this
page lists what is sent, what counts as a positive, the options that steer it and
the limits of the evidence. Option defaults are in [`OPTIONS.md`](OPTIONS.md).

Statuses used below are defined in [`REPORT-FORMAT.md`](REPORT-FORMAT.md#finding-statuses).

- [Version fingerprint and assessment](#fingerprint)
- [Authorization bypasses](#authorization-bypasses): `base-bypass`, `encoded-path`
- [Reflected XSS](#reflected-xss): `transition-xss`, `transition-directive-xss`,
  `spread-attrs-xss`, `custom-element-xss`, `slot-xss`, `define-vars-xss`,
  `dev-error-xss`, `server-island-reflected-xss`
- [Server-island replay](#server-island-replay)
- [astro/hono CSRF](#hono-csrf)
- [remotePatterns bypass](#remote-pattern-bypass)
- [Source maps](#sourcemaps)
- [Controlled-callback SSRF](#controlled-callback-ssrf): `host-header-ssrf`, `image-proxy-ssrf`
- [Not covered](#not-covered)

---

## fingerprint

Always runs first (it is the preflight), whether requested or not.

**Requests.** `GET /`, then up to `--max-version-artifact-requests` (default 8)
artifact requests: every `--version-path`, the default artifacts
`/package.json`, `/package-lock.json`, `/pnpm-lock.yaml`, `/yarn.lock` (disable
with `--no-version-probe-default-artifacts`), and `.map` candidates derived from
same-origin `<script src>`/`<link href>` `.js` URLs on the homepage.

**Exact version sources.** A version is accepted only if it is a valid semantic
version (`X.Y.Z` with optional pre-release/build) found in:

| Source label | Where |
|---|---|
| `html-generator-meta` | `<meta name="generator" content="Astro vX.Y.Z">` |
| `http-header:x-powered-by`, `http-header:server` | `Astro/X.Y.Z` style header values |
| `package.json` | `dependencies` / `devDependencies` / `peerDependencies` `astro` entry |
| `package-lock.json` | `packages["node_modules/astro"].version` or a matching lock line |
| `pnpm-lock.yaml`, `yarn.lock` | `astro@X.Y.Z` style lock lines |
| `source-map:sourcesContent` | `Astro vX.Y.Z`, `astro@X.Y.Z` or `"astro": "X.Y.Z"` inside embedded sources |

Generic signals (`<astro-island>`, `/_astro/*.js`, the word "Astro") are recorded
as `signals` but never produce a version.

**Statuses.** `astro-version-identified`, `astro-candidate` (signals but no
version) or `no-astro-signal`. Confidence is `high` when the version comes from
generator metadata or a package/lock file, `medium` for header/source-map
sources.

**Version assessment.** With an exact version, every `advisories/GHSA-*.json`
record whose `SEMVER` range for the npm package `astro` contains that version is
listed, sorted by severity (`CRITICAL` → `LOW`). Ranges honour `introduced`,
`fixed` and `last_affected`. This is an upgrade-candidate list only: a match says
nothing about whether the affected feature, route, adapter or input exists on the
target.

> Note on range evaluation: version comparison uses the numeric `major.minor.patch`
> triple; pre-release tags are ignored when comparing.

---

## Authorization bypasses

Both modules require `--marker`: a string that only appears in the protected
response (for example a heading or value from the admin page). A module run
without it is refused.

Positive logic, shared by both:

| Baseline (`--protected-path`) | Bypass request | Status |
|---|---|---|
| `401` or `403` | `200` and body contains `--marker` | `vulnerable` (high) |
| `401` or `403` | anything else | `not-vulnerable-or-not-applicable` (medium) |
| not `401/403` | — | `inconclusive` (low) |

### base-bypass

CVE-2026-84376 / GHSA-376h-93r7-7g6f — fixed in Astro 7.2.4.

Astro stripped a non-root `base` without checking for a path-segment boundary, so
`/appX/admin` was routed as `/admin` while pathname-based middleware only guarded
`/app/admin`.

- Baseline: `GET <base-path><protected-path>` (default `/app/admin`).
- Bypass: `GET <base-path><suffix><protected-path>` (default `/appX/admin`).
- Options: `--base-path` (must not be `/`), `--protected-path`, `--marker`,
  `--base-bypass-suffix` (one path segment fragment, no `/`).

### encoded-path

Three checks against the same baseline (`GET <protected-path>`), encoding the
first letter of the first path segment:

| Advisory | Fixed in | Encoding | Example for `/admin` |
|---|---|---|---|
| CVE-2025-64765 / GHSA-ggxq-hp9w-j794 | 5.15.8 | `--single-encoding-depth` (default 1) | `/%61dmin` |
| CVE-2025-66202 / GHSA-whqg-ppgf-wp8c | 5.15.8 | double | `/%2561dmin` |
| CVE-2026-59731 / GHSA-vj59-8hwv-xxmv | 6.4.8 | `--deep-encoding-depth` (default 12) | `/%252525252525252525252561dmin` |

Depth counts decode passes: depth 12 yields the advisory's literal payload
(eleven `25` layers). The first path segment must start with an ASCII letter.

**Limits.** Only pathname-based middleware is exercised; application-specific
guards (rewrites, adapters, edge rules) may differ.

---

## Reflected XSS

All XSS modules share one proof technique: the payload breaks out of the
vulnerable context and inserts

```html
<astro-scan-xss data-token="<random 128-bit hex>"></astro-scan-xss>
```

an **inert custom element** with a per-run token. The scanner then classifies
where the marker landed:

- raw, outside any `<script>` → `vulnerable` (`html_context: raw`);
- raw but inside a still-open `<script>` (for example JSON-LD) → not a positive
  (`html_context: script-data`);
- URL-encoded or HTML-escaped, or absent → not a positive
  (`html_context: escaped-or-absent`).

A positive proves the HTML-parser breakout needed for XSS. No JavaScript is
executed and none is sent. If a program requires executable proof, replace the
marker manually and only if its policy allows it.

The sink is application-specific: you must know (or have found) the route and
query parameter that flow into the affected Astro API. Absence of the marker is
**not** evidence of a fixed version.

| Module | Advisory | Fixed in | Payload shape | Options (default) |
|---|---|---|---|---|
| `transition-xss` | CVE-2026-73422 / GHSA-4g3v-8h47-v7g6 — View Transition animation values | 7.1.0 | `</style>` + marker + `<!--` | `--transition-path` (`/`), `--transition-param` (`duration`) |
| `transition-directive-xss` | CVE-2026-59727 / GHSA-7pw4-f3q4-r2p2 — `transition:*` directive on hydrated islands | 7.0.4 | `">` + marker | `--transition-directive-path` (`/`), `--transition-directive-param` (`persist`) |
| `spread-attrs-xss` | CVE-2026-54298 / GHSA-jrpj-wcv7-9fh9 — attribute names in spread props | 6.4.6 | JSON object whose **key** is `x">` + marker + `<b y` | `--spread-attrs-path` (`/`), `--spread-attrs-param` (`props`) |
| `custom-element-xss` | CVE-2026-59729 / GHSA-f48w-9m4c-m7f5 — spread names in `renderHTMLElement` (incomplete fix of the above) | 7.0.6 | same JSON-key payload | `--custom-element-path` (`/`), `--custom-element-param` (`props`) |
| `slot-xss` | CVE-2026-50146 / GHSA-8hv8-536x-4wqp — dynamic slot name on hydrated islands | 6.3.3 | `astro"></template></astro-island>` + marker + `<!--` | `--slot-path` (`/`), `--slot-param` (`tab`) |
| `define-vars-xss` | CVE-2026-41067 / GHSA-j687-52p2-xcff — `define:vars` `</script>` sanitization | 6.1.6 | `</Script>` + marker | `--define-vars-path` (`/`), `--define-vars-param` (`name`) |
| `dev-error-xss` | CVE-2025-64745 / GHSA-w2vj-39qv-7vh7 — dev-server 404/error page | 5.15.6 | path `/"></script>` + marker + `<!--` (URL-encoded) | `--trailing-slash-mode` (`never` appends `/`, `always` does not) |
| `server-island-reflected-xss` | CVE-2025-64764 / GHSA-wrwg-2hg8-v723 — arbitrary template via server-island slots | 5.15.8 | `GET /_server-islands/<name>?e=file&p=&s={"<slot>":"<marker>"}` | `--server-island-reflected-name` (`ComponentA`), `--server-island-reflected-slot` (`astro-scan`) |

`dev-error-xss` targets the **development server** (`astro dev`). Use it only where
an exposed dev server is explicitly in scope.

---

## server-island-replay

CVE-2026-45028 / GHSA-xr5h-phrj-8vxv — fixed in Astro 6.1.10.

Server-island props were encrypted without binding the ciphertext to its
component or to prop-versus-slot usage, so an encrypted prop from one island could
be replayed as the slots of another.

1. `GET <server-island-path>?<server-island-param>=<marker>` so that your marker
   ends up as an encrypted prop of the source island.
2. Parse the page for `/_server-islands/<source>?…p=…` and
   `/_server-islands/<target>?…e=…`.
3. `GET /_server-islands/<target>?e=<target export>&p=&s=<source ciphertext>`.

Positive: the replay response contains the marker raw. If either island reference
is missing, the result is `not-vulnerable-or-not-applicable` with the reason.

Options: `--server-island-path` (`/`), `--server-island-param` (`shared`),
`--server-island-source-name` (`ComponentA`), `--server-island-target-name`
(`ComponentB`).

**Limits.** Requires the rare shape described in the advisory: two islands that
share a prop/slot name and an attacker-influenced source prop.

---

## hono-csrf

CVE-2026-73423 / GHSA-8mv7-9c27-98vc — fixed in Astro 7.0.6.

In composable `astro/hono` pipelines, `security.checkOrigin` was skipped when
`middleware()` was not composed before `actions()`/`pages()`.

Sends one cross-origin, form-like request:

```
<--hono-csrf-method> <--hono-csrf-path>
Origin: <--hono-csrf-origin>
Content-Type: <--hono-csrf-content-type>

<--hono-csrf-body>
```

Positive: `200` **and** the response contains `--hono-csrf-marker`.

This module **changes state** by design. It is refused unless both
`--allow-state-changing-check` and `--hono-csrf-marker` are given. Point it only at
a harmless endpoint that you own or that the program designates. A `403` alone is
not evidence either way.

Options: `--hono-csrf-path` (`/api/delete`), `--hono-csrf-method` (`POST`; also
`PUT`, `PATCH`, `DELETE`), `--hono-csrf-origin`
(`http://astro-scan-cross-origin.invalid`), `--hono-csrf-content-type`
(`application/x-www-form-urlencoded`), `--hono-csrf-body`
(`astro-scan-csrf-proof=1`).

---

## remote-pattern-bypass

CVE-2026-33769 / GHSA-g735-7g2w-hh3f — fixed in Astro 5.18.1.

`remotePatterns` wildcard paths were matched without anchoring, so a URL outside
the configured prefix could pass the allowlist.

Sends two image-endpoint requests (`<--remote-pattern-path>?href=…&f=svg`):

1. the allowed control (`--remote-pattern-allowed-href`);
2. the bypass (`--remote-pattern-bypass-href`).

Positive: both return `200` and contain `--remote-pattern-marker`.

Both URLs must point to a host **you control** that serves the marker; the module
is refused without `--i-control-remote-host` and all three values. Default path
`/_image`.

---

## sourcemaps

CVE-2024-56159 / GHSA-49w6-73cw-chjr — fixed in Astro 5.0.8 / 4.16.18.

With source maps enabled, server bundles and their maps could be published to the
client output.

Requests `GET /`, then up to `--max-sourcemap-requests` (20) candidates:
`--sourcemap-path` values, `.map` siblings of same-origin homepage scripts, and
the defaults `/pages/index.astro.mjs.map`, `/dist/server/entry.mjs.map`,
`/server/entry.mjs.map`, `/entry.mjs.map`.

Positive: a `200` JSON document with `version` and a `sources` list. The evidence
records the path, hash, source count, the first eight source names and the number
of embedded `sourcesContent` entries; it stops after `--max-source-map-findings`
(3).

**Limits.** Proves source disclosure. Severity rises only if the disclosed source
contains secrets or sensitive logic — review it manually.

---

## Controlled-callback SSRF

Both modules need a callback URL. Choose one:

- `--callback-listen HOST:PORT` — AstroScan starts its own HTTP listener and
  generates `http://<host>:<port>/astro-callback-<token>.svg`. When listening on
  `0.0.0.0`, set `--callback-advertise-host` to the address the target can reach.
- `--callback-url URL` — an external host you control. Its path should end in
  `astro-callback-<token>.svg` and it should answer with the body
  `astro-scan-callback:<token>`, so reflection can be proven.

Either way `--i-control-callback` is mandatory. The modules never target internal
addresses or third-party hosts. If no callback is configured, the SSRF modules are
skipped silently. Wait time per check: `--callback-timeout` (5 s).

### host-header-ssrf

CVE-2026-54299 / GHSA-2pvr-wf23-7pc7 — fixed in Astro 6.4.6 (with the matching
Node adapter).

Prerendered error pages were fetched from a URL built from the request `Host`
header.

Sends `GET <--error-path>` (default `/astro-scan-nonexistent`) with
`Host: <callback host:port>`.

| Callback received | Token reflected in response | Status |
|---|---|---|
| yes | yes | `vulnerable` (high) |
| yes | no | `callback-observed` (medium) — outbound fetch only |
| no | — | `not-vulnerable-or-not-applicable` |

With an external `--callback-url` the scanner cannot see the callback log; a
reflected token is then taken as proof of both.

### image-proxy-ssrf

CVE-2025-59837 / GHSA-qcpr-679q-rhm2 — fixed in Astro 5.13.10.

The image endpoint's domain check could be bypassed with a backslash-prefixed
`href`.

Sends `GET <--image-path>?href=\\<callback-host[:port]>/<path>&f=<--image-format>`
(defaults `/_image`, `svg`).

Positive: the callback was received **or** the response contains the callback
token.

**Limits.** Proves a controlled outbound request only. Internal-network impact
needs separate, explicit authorization and is out of scope for this tool.

---

## Not covered

- **GHSA-26w7-cxv4-gfx2** (AVIF/libheif heap overflow through Sharp, fixed in
  Astro 7.2.8 / Sharp 0.35.4): the crafted memory-corruption input is
  intentionally **never** sent to a target. The version assessment still flags
  affected versions.
- Other advisories in `advisories/` (open redirect, `X-Forwarded-Host`
  reflection, dev-server file read, Cloudflare stored XSS, DOM clobbering…) are
  reported by the version assessment only, without an active check.
