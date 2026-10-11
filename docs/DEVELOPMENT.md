# Development

## Tests

The unit tests cover origin normalization, path encoding, version extraction and
range matching, the HTML-context classifier, URL builders for the server-island
and image-proxy modules, the callback listener and the human report. They make no
network connection to external hosts.

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

1. Add the name to `SUPPORTED_MODULES`.
2. Write `run_<module>(client, target, args) -> Finding`. Use `client.request`
   (it records every transaction) and `args.delay` between requests.
3. Define the positive criterion so that it **discriminates**: compare against a
   baseline or control, and require a marker or token that only the vulnerable
   behaviour can produce. Fill `limitations` with what the positive does not
   prove.
4. Add the options in `parse_args()` and any mandatory-input check in
   `validate_args()` so that a run without them is refused before sending.
5. Dispatch it in `run()`.
6. Validate it against a vulnerable/fixed pair of Astro builds: add a fixture
   under `lab/` and a pair of `assert_vulnerable`/`assert_fixed` steps to
   `lab/run_priority_matrix.sh` (see [`LAB.md`](LAB.md)).
7. Add unit tests for any payload or URL builder, and document the module in
   `docs/MODULES.md`, `docs/OPTIONS.md` and the README table.

## Style

- Standard library only; single file.
- Never add payloads that execute code, exfiltrate data, or target hosts other
  than the authorized target and operator-controlled callbacks.
