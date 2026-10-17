# Development

## Tests

The unit tests cover origin normalization (including IPv6), path encoding,
version extraction and range matching, the HTML-context classifier, URL builders
for the server-island and image-proxy modules, the callback listener, profiles
and skip planning, config/list/header/cookie parsing, request-header redaction,
decompression, redirect/retry/budget behaviour of the HTTP client, SARIF output
and the human report. They make no network connection to external hosts; the HTTP
client tests use a loopback fixture.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Version-range tests read the bundled `advisories/` directory, so keep it in place.

## Refreshing the advisory database

`advisories/` holds one OSV-format JSON record per GitHub advisory affecting the
npm package `astro` (plus the Sharp/libheif root record). The version assessment
reads every `GHSA-*.json` file and uses its `affected[].ranges[]` entries of type
`SEMVER` for the package `astro`.

To add or refresh a record:

```bash
curl -fsSL https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx \
  -o advisories/GHSA-xxxx-xxxx-xxxx.json
```

To list all current Astro advisories:

```bash
curl -fsSL https://api.osv.dev/v1/query \
  -d '{"package":{"name":"astro","ecosystem":"npm"}}' \
  | python3 -c 'import json,sys; [print(v["id"]) for v in json.load(sys.stdin)["vulns"]]'
```

Then run the tests and check that the expected advisories match a known
vulnerable version and stop matching at the fixed version.

## Adding a module

1. Add the name to `SUPPORTED_MODULES` and `MODULE_REQUIREMENTS`.
2. Write `run_<module>(client, target, args) -> Finding`. Use `client.request`
   (it records every transaction and enforces `--delay`, `--rate-limit`,
   retries, redirect policy and `--max-requests`; do not sleep in the module).
3. Define the positive criterion so that it **discriminates**: compare against a
   baseline or control, and require a marker or token that only the vulnerable
   behaviour can produce. Fill `limitations` with what the positive does not
   prove. A transport error must yield `inconclusive`, not a negative result.
4. Add the options in `parse_args()`, any config key in `CONFIG_KEYS`, and any
   mandatory-input check in `module_missing_inputs()` so that explicit requests
   fail before sending while profiles/`all` can skip with a reason.
5. Dispatch it in `module_finding()`.
6. Validate it against a vulnerable/fixed pair of Astro builds: add a fixture
   under `lab/` and a pair of `assert_vulnerable`/`assert_fixed` steps to
   `lab/run_priority_matrix.sh` (see [`LAB.md`](LAB.md)).
7. Add unit tests for any payload or URL builder, and document the module in
   `docs/MODULES.md`, `docs/OPTIONS.md` and the README table.

## Style

- Standard library only; single file.
- Never add payloads that execute code, exfiltrate data, or target hosts other
  than the authorized target and operator-controlled callbacks.
