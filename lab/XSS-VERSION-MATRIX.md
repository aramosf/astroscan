# Astro XSS version matrix

Updated: 2026-10-11

The scanner uses an inert custom element rather than executable JavaScript. A positive means the request value crossed the relevant HTML parser boundary and was emitted as raw HTML; this is the required primitive for XSS without causing a dialog, data access, or script execution during testing.

| Runtime | Astro | Checks | Result | Control |
|---|---:|---|---|---|
| SSR/dev fixture | 6.1.5 | `define:vars` | Raw script-context breakout | 6.1.6 escapes the payload |
| SSR/dev fixture | 6.3.1 | View Transition, hydrated slot | Both raw HTML injections | 6.3.3 fixes slot; View Transition remains affected until 7.1.0 |
| SSR/dev fixture | 6.3.3 | View Transition | Raw `<style>` breakout | 7.1.0 escapes the payload |
| Production Node fixture | 7.0.9 | View Transition | Raw `<style>` breakout | 7.1.0 escapes the payload |
| Development server | 5.15.5 | Trailing-slash 404 page | Raw error-page HTML injection | 5.15.6 escapes the payload |

## Reproduction

```bash
./lab/build_xss_labs.sh
./lab/verify_xss_versions.sh
```

The script asserts every vulnerable/fixed pair above and writes JSON evidence to `evidence/xss-matrix/`.

## Runtime note

Astro 6 fixtures run through the development renderer because the published Astro 6.x Node adapter combinations tested here fail at runtime with `app.getAdapterLogger is not a function` or a missing `createRequestFromNodeRequest` export. This does not alter the request, route, query parameter, or renderer sink used by the differential test, but production-adapter impact for those two rows remains a documented gap. Astro 7 View Transition checks run in the production standalone Node runtime.
