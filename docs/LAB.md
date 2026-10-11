# Laboratories

`lab/` contains Docker fixtures that build the **same small Astro application on a
vulnerable release and on the first fixed release**. Every scanner module is
validated against such a pair: it must report `vulnerable` on the first and
`no-confirmed-finding` on the second. Everything listens on `127.0.0.1` only, so
the scanner needs no authorization flags.

## Requirements

- Docker (with `docker compose` for the libheif labs).
- `curl`, `jq`, Python 3.11+.
- Network access to the npm registry and Docker Hub while building images.

## Suites

| Script | What it proves | Output |
|---|---|---|
| `lab/run_priority_matrix.sh` | Eleven vulnerable/fixed pairs, driven through `src/astro_scan.py` | `evidence/priority-matrix/*.json`, `REGRESSION-SUMMARY.tsv`, `SHA256SUMS.txt` |
| `lab/build_xss_labs.sh` + `lab/verify_xss_versions.sh` | Multi-version XSS matrix (see `lab/XSS-VERSION-MATRIX.md`) | `evidence/xss-matrix/` |
| `lab/verify_base_bypass.sh` | CVE-2026-84376 end-to-end: `/app/admin` → `403`, `/appX/admin` → `200` + `ADMIN_SECRET` on 7.2.3; fixed on 7.2.4 | `lab/artifacts/CVE-2026-84376-base-bypass.log` |
| `lab/run_libheif_asan.sh` | GHSA-26w7-cxv4-gfx2 root cause: heap out-of-bounds write in libheif 1.23.1 under ASan | `lab/artifacts/` |
| `lab/verify_fixed_control.sh` | Same input rejected cleanly by libheif 1.23.2 | `lab/artifacts/` |
| `lab/verify_astro_image_route.sh` | Astro 7.2.7 / Sharp 0.35.3 `/_image` route reaches the vulnerable decoder (run `run_libheif_asan.sh` first: it generates the input) | `lab/artifacts/` |

Run them from the repository root:

```bash
./lab/run_priority_matrix.sh

./lab/build_xss_labs.sh
./lab/verify_xss_versions.sh

./lab/verify_base_bypass.sh

./lab/run_libheif_asan.sh
./lab/verify_fixed_control.sh
./lab/verify_astro_image_route.sh
```

`evidence/` and `lab/artifacts/` are generated and git-ignored.

## Priority matrix pairs

| Module | Fixture | Vulnerable | Fixed |
|---|---|---|---|
| `transition-directive-xss` | `transition-directive-app` | 7.0.3 | 7.0.4 |
| `spread-attrs-xss` | `spread-attrs-app` | 6.4.5 | 6.4.6 |
| `custom-element-xss` | `custom-element-app` | 7.0.5 | 7.0.6 |
| `hono-csrf` | `hono-origin-app` | 7.0.5 | 7.0.6 |
| `remote-pattern-bypass` | `remote-patterns-app` (+ `remote.Dockerfile` marker server) | 5.18.0 | 5.18.1 |
| `encoded-path` (deep) | `deep-encoded-app` | 6.4.7 | 6.4.8 |
| `host-header-ssrf` | `host-header-app` + `callback/` | 6.4.5 | 6.4.6 |
| `server-island-replay` | `server-island-app` | 6.1.9 | 6.1.10 |
| `server-island-reflected-xss` | `server-island-app` | 5.15.7 | 5.15.8 |
| `sourcemaps` | `sourcemap-app` | 5.0.6 | 5.0.7 |
| `image-proxy-ssrf` | `cloudflare-image-app` | 5.13.4 + Cloudflare adapter 12.6.8 | 5.13.10 + adapter 12.6.10 |

The same run also asserts that the fingerprint extracts the exact versions
`6.4.5` and `6.4.6` from the host-header fixtures. The SSRF fixtures share a
private Docker network (`astro-priority-matrix`) with the `callback/` container,
so no request leaves the host.

## Fixture layout

Each `*-app/` directory is a minimal Astro project (`package.json`,
`astro.config.mjs`, `src/`, `Dockerfile`). The Astro version (and, where relevant,
the adapter version) is a Docker build argument, so one fixture serves both sides
of a pair:

```bash
docker build -t astro-spread-attrs-6.4.5:fixture --build-arg ASTRO_VERSION=6.4.5 lab/spread-attrs-app
docker run --rm -d -p 127.0.0.1:4321:4321 astro-spread-attrs-6.4.5:fixture
python3 src/astro_scan.py --target http://127.0.0.1:4321 --modules spread-attrs-xss
```

`app/` and `base-app/` are the pinned applications for the image-route and
base-path labs; `Dockerfile` + `docker-compose.yml` at the top of `lab/` build
libheif 1.23.1 / 1.23.2 with ASan.

## Memory-corruption input

`lab/generate_heic_poc.py` builds the crafted HEIC for the libheif issue. It is a
**local** reproducer: the generated file is written to `lab/artifacts/`, copied
only into the local `app/` fixture, and is never used by the scanner against a
target.

## Known gaps

- Astro 6 XSS rows run on the development renderer because the tested Astro 6
  Node adapter combinations fail at runtime; see `lab/XSS-VERSION-MATRIX.md`.
- The image-route lab proves decoder reachability through Sharp, not a crash of
  the stock Astro process: Sharp catches the decode failure and returns the
  original file.
