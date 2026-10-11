# Evidence report format

`--output PATH` writes one JSON document per run (`--format json` prints the same
document). Keys are sorted; the schema identifier is `astro-scan-evidence/1`.

## Top level

| Key | Type | Content |
|---|---|---|
| `schema` | string | `astro-scan-evidence/1` |
| `generated_at` | string | UTC timestamp, ISO 8601 with `Z` |
| `scanner` | string | Scanner path identifier |
| `target` | string | Normalized target origin |
| `target_local` | bool | Target is loopback/`localhost` |
| `authorization` | object | `scope` (normalized origins), `authorization_statement`, `remote_testing_allowed`, `policy` |
| `configuration` | object | `modules` (executed list), `timeout_seconds`, `delay_seconds`, `marker_supplied` |
| `astro_versions` | array of string | Distinct exact versions found by the fingerprint (empty if none) |
| `version_assessment` | object | See below |
| `findings` | array | One object per module result (`encoded-path` yields three) |
| `http_transactions` | array | Every request made, in order |
| `overall_status` | string | `vulnerable` if any finding is `vulnerable`, else `no-confirmed-finding` |
| `limitations` | array of string | Global limits of the run |

## version_assessment

```json
{
  "matched_count": 2,
  "advisories": [
    {
      "id": "GHSA-wrwg-2hg8-v723",
      "aliases": ["CVE-2025-64764"],
      "severity": "HIGH",
      "summary": "Astro vulnerable to reflected XSS via the server islands feature",
      "introduced": "0",
      "fixed": "5.15.8",
      "last_affected": null
    }
  ],
  "boundary": "Version matches identify upgrade candidates; ..."
}
```

Without an exact version `matched_count` is `0` and `boundary` explains why.

## Finding

| Key | Content |
|---|---|
| `module` | Module name |
| `identifier` | `CVE-… / GHSA-…` (or `ASTRO-FINGERPRINT`) |
| `title` | Short description |
| `status` | See statuses below |
| `confidence` | `high`, `medium` or `low` |
| `evidence` | Module-specific object; always references the `id` of the HTTP transactions it relies on |
| `remediation` | Suggested fix |
| `references` | Advisory/commit URLs |
| `limitations` | What the evidence does **not** prove |

### Finding statuses

| Status | Meaning |
|---|---|
| `vulnerable` | The module's positive criterion was met. See [`MODULES.md`](MODULES.md). |
| `callback-observed` | `host-header-ssrf` only: the target fetched the callback but did not reflect it. |
| `not-vulnerable-or-not-applicable` | Criterion not met. This includes "feature or sink not present"; it is not a statement about the version. |
| `inconclusive` | Bypass modules only: the baseline was not `401/403`, so a bypass cannot be judged. |
| `astro-version-identified` | Fingerprint found an exact version. |
| `astro-candidate` | Fingerprint saw Astro signals but no exact version. |
| `no-astro-signal` | Fingerprint saw nothing Astro-specific. |

### Common evidence fields

- Bypass modules: `baseline_status`, `baseline_auth_blocked`, `bypass_path`,
  `bypass_status`, `protected_content_marker` (`present`, `first_index`,
  `context`).
- XSS modules: `safe_payload`, `html_injection` (`present`, `html_context` =
  `raw` | `script-data` | `escaped-or-absent`, `context`, `first_index`).
- SSRF modules: `callback_events` (timestamp, client IP, method, path, redacted
  headers), `callback_response_reflected` / `callback_token_returned`.
- `sourcemaps`: `tested_paths`, `valid_source_maps` (path, SHA-256, counts,
  sample source names).
- `fingerprint`: `signals`, `astro_version`, `version_evidence`
  (`version`, `source`, `detail`).

## HTTP transaction

```json
{
  "id": "req-1a2b3c4d5e6f",
  "timestamp": "2026-10-11T10:00:00Z",
  "elapsed_ms": 41.7,
  "method": "GET",
  "url": "https://app.example.com/appX/admin",
  "request_headers": {"user-agent": "AstroScan/1.0 (authorized-security-test)", "accept": "*/*"},
  "status": 200,
  "reason": "OK",
  "response_headers": {"content-type": "text/html", "set-cookie": "<redacted>"},
  "body_sha256": "…",
  "body_length": 5120,
  "body_truncated": false,
  "body_preview": "first 512 characters, control characters replaced"
}
```

- Response bodies are read up to 1 MiB; `body_sha256` and `body_length` refer to
  what was read, `body_truncated` flags the cut.
- `Set-Cookie`, `WWW-Authenticate` and `Proxy-Authenticate` response headers are
  replaced by `<redacted>`. **Request** headers are stored as sent — do not pass
  secrets through options that end up in headers or bodies.
- A failed request has `error` (`"<ExceptionType>: <message>"`) instead of
  `status`/`reason`/body fields.

## Terminal report

The human format prints the target, the authorization flag, the detected version,
the severity-sorted advisory list, then one block per finding with its status,
the most relevant evidence fields and its limitations, followed by totals and the
evidence file path.
