#!/usr/bin/env python3

import gzip
import http.server
import json
import tempfile
import threading
import unittest
import urllib.parse
import zlib
from pathlib import Path
from types import SimpleNamespace

import astro_scan


class AstroScanTests(unittest.TestCase):
    def test_normalize_origin(self):
        self.assertEqual(astro_scan.normalize_origin("https://Example.com./"), "https://example.com")
        self.assertEqual(astro_scan.normalize_origin("http://localhost:8080/path"), "http://localhost:8080")

    def test_depth_encoding(self):
        self.assertEqual(astro_scan.depth_encode_path("/admin", 1), "/%61dmin")
        self.assertEqual(astro_scan.depth_encode_path("/admin", 2), "/%2561dmin")
        self.assertEqual(astro_scan.depth_encode_path("/admin", 12), "/%252525252525252525252561dmin")

    def test_base_paths(self):
        self.assertEqual(
            astro_scan.canonical_path("/app") + "X" + astro_scan.canonical_path("/admin"),
            "/appX/admin",
        )

    def test_source_map_candidates(self):
        body = '<script src="/_astro/page.123.js"></script><script src="https://cdn.example.com/x.js"></script>'
        self.assertEqual(
            astro_scan.source_map_candidates(body, ["/custom.map"], 5),
            ["/custom.map", "/_astro/page.123.js.map"],
        )

    def test_raw_html_injection_evidence(self):
        token = "0123456789abcdef"
        marker = f'<astro-scan-xss data-token="{token}"></astro-scan-xss>'
        raw = astro_scan.raw_html_injection_evidence(f"before {marker} after".encode(), token)
        escaped = astro_scan.raw_html_injection_evidence(
            f"before {astro_scan.html.escape(marker)} after".encode(), token
        )
        self.assertTrue(raw["present"])
        self.assertEqual(raw["html_context"], "raw")
        self.assertFalse(escaped["present"])

    def test_raw_marker_inside_script_data_is_not_html_injection(self):
        token = "0123456789abcdef"
        marker = f'<astro-scan-xss data-token="{token}"></astro-scan-xss>'
        body = f'<script type="application/ld+json">{{"id":"{marker}"}}</script>'.encode()
        evidence = astro_scan.raw_html_injection_evidence(body, token)
        self.assertTrue(evidence["raw_marker_seen"])
        self.assertFalse(evidence["present"])
        self.assertEqual(evidence["html_context"], "script-data")

    def test_case_insensitive_script_close_breakout_is_html_injection(self):
        token = "0123456789abcdef"
        marker = f'<astro-scan-xss data-token="{token}"></astro-scan-xss>'
        body = ('<script>closed</script><script>const value = "</Script>' + marker + ';</script>').encode()
        evidence = astro_scan.raw_html_injection_evidence(body, token)
        self.assertTrue(evidence["present"])
        self.assertEqual(evidence["html_context"], "raw")

    def test_callback_listen_advertises_reachable_host(self):
        args = SimpleNamespace(
            callback_listen="0.0.0.0:0",
            callback_url=None,
            callback_advertise_host="172.17.0.1",
        )
        server, callback_url = astro_scan.start_callback(args)
        try:
            self.assertIsNotNone(callback_url)
            self.assertTrue(callback_url.startswith("http://172.17.0.1:"))
            self.assertIn("astro-callback-", callback_url)
        finally:
            server.stop()

    def test_astro_version_extraction(self):
        html_body = b'<head><meta name="generator" content="Astro v6.4.5"></head>'
        self.assertEqual(
            astro_scan.extract_astro_versions(html_body, {}),
            [{"version": "6.4.5", "source": "html-generator-meta", "detail": "Astro v6.4.5"}],
        )

        package = json.dumps({"dependencies": {"astro": "7.1.0"}}).encode()
        self.assertEqual(
            astro_scan.extract_astro_versions(package, {}, "/package.json"),
            [{"version": "7.1.0", "source": "package.json", "detail": "$dependencies.astro"}],
        )

        lock = json.dumps({"packages": {"node_modules/astro": {"version": "6.1.10"}}}).encode()
        self.assertEqual(
            astro_scan.extract_astro_versions(lock, {}, "/package-lock.json"),
            [{"version": "6.1.10", "source": "package-lock.json", "detail": "node_modules/astro"}],
        )

    def test_valid_astro_version_rejects_non_semver(self):
        self.assertTrue(astro_scan.valid_astro_version("6.4.5-beta.1"))
        self.assertFalse(astro_scan.valid_astro_version("6.4"))

    def test_human_report_reflects_findings(self):
        report = {
            "target": "https://example.com",
            "generated_at": "2026-10-11T00:00:00Z",
            "authorization": {"remote_testing_allowed": True},
            "astro_versions": ["5.12.3"],
            "overall_status": "vulnerable",
            "http_transactions": [{"id": "request"}],
            "output_file": "evidence.json",
            "findings": [
                {
                    "module": "test-module",
                    "title": "Test vulnerability",
                    "status": "vulnerable",
                    "confidence": "high",
                    "identifier": "CVE-0000-0000",
                    "evidence": {"response_status": 200, "callback_token_returned": True},
                    "limitations": ["Test limitation"],
                }
            ],
        }
        rendered = astro_scan.render_human_report(report)
        self.assertIn("[VULNERABLE] test-module — Test vulnerability", rendered)
        self.assertIn("Advisory: CVE-0000-0000", rendered)
        self.assertIn("response status: 200", rendered)
        self.assertIn("callback token returned: yes", rendered)
        self.assertIn("Overall: VULNERABLE", rendered)

    def test_version_advisory_assessment_matches_fixed_boundary(self):
        assessment = astro_scan.applicable_version_advisories("5.15.7")
        identifiers = {advisory["id"] for advisory in assessment["advisories"]}
        self.assertIn("GHSA-wrwg-2hg8-v723", identifiers)
        self.assertGreater(assessment["matched_count"], 0)

        fixed = astro_scan.applicable_version_advisories("5.15.8")["advisories"]
        reflected = next((item for item in fixed if item["id"] == "GHSA-wrwg-2hg8-v723"), None)
        self.assertIsNone(reflected)
        self.assertFalse(astro_scan.valid_astro_version("latest"))

    def test_server_island_replay_url_uses_source_prop_as_target_slot(self):
        body = (
            '<link href="/_server-islands/ComponentA?e=A&p=source-ciphertext&s=">'
            '<link href="/_server-islands/ComponentB?e=B&p=&s=target-ciphertext">'
        )
        url = astro_scan.server_island_replay_url("http://127.0.0.1:4321", body, "ComponentA", "ComponentB")
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(parsed.path, "/_server-islands/ComponentB")
        self.assertEqual(query["e"], ["B"])
        self.assertEqual(query["p"], [""])
        self.assertEqual(query["s"], ["source-ciphertext"])

    def test_server_island_reflected_xss_url_uses_file_export_and_slot_payload(self):
        url = astro_scan.server_island_reflected_xss_url(
            "http://127.0.0.1:4321",
            "ComponentA",
            "astro-scan",
            "<astro-scan-xss></astro-scan-xss>",
        )
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(parsed.path, "/_server-islands/ComponentA")
        self.assertEqual(query["e"], ["file"])
        self.assertEqual(query["p"], [""])
        self.assertEqual(query["s"], ['{"astro-scan":"<astro-scan-xss></astro-scan-xss>"}'])

    def test_image_proxy_ssrf_url_uses_backslash_scheme_bypass(self):
        url = astro_scan.image_proxy_ssrf_url(
            "http://127.0.0.1:4321",
            "/_image",
            "http://callback.example:9999/astro-callback-token.svg",
            "svg",
        )
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(parsed.path, "/_image")
        self.assertEqual(query["href"], ["\\\\callback.example:9999/astro-callback-token.svg"])
        self.assertEqual(query["f"], ["svg"])

    def test_normalize_origin_brackets_ipv6(self):
        self.assertEqual(astro_scan.normalize_origin("http://[::1]:8080/path"), "http://[::1]:8080")
        self.assertEqual(astro_scan.normalize_origin("https://[2001:db8::1]/"), "https://[2001:db8::1]")

    def test_scope_file_comments_and_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scopes.txt"
            path.write_text("# authorized\nhttps://Example.com/\n\nhttp://127.0.0.1:4321\n", encoding="utf-8")
            self.assertEqual(
                astro_scan.parse_scope_values([], path),
                ["https://example.com", "http://127.0.0.1:4321"],
            )

    def test_scope_rejects_paths(self):
        with self.assertRaises(ValueError):
            astro_scan.parse_scope_values(["https://example.com/app"], None)

    def test_header_cookie_and_resolve_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            header_path = Path(directory) / "headers.txt"
            header_path.write_text("# comment\nX-Research: yes\n", encoding="utf-8")
            cookie_path = Path(directory) / "cookies.txt"
            cookie_path.write_text("session=abc\nCookie: theme=dark\n", encoding="utf-8")
            self.assertEqual(
                astro_scan.parse_header_values(["Authorization: Bearer x"], header_path),
                {"Authorization": "Bearer x", "X-Research": "yes"},
            )
            self.assertEqual(
                astro_scan.parse_cookie_values([], cookie_path),
                "session=abc; theme=dark",
            )
        self.assertEqual(
            astro_scan.parse_resolve_values(["example.com:443:127.0.0.1", "[::1]:8443:127.0.0.1"]),
            {("example.com", 443): "127.0.0.1", ("::1", 8443): "127.0.0.1"},
        )

    def test_request_header_redaction(self):
        headers = {"Authorization": "Bearer secret", "Cookie": "a=b", "X-Test": "ok"}
        self.assertEqual(
            astro_scan.sanitized_request_headers(headers),
            {"authorization": "<redacted>", "cookie": "<redacted>", "x-test": "ok"},
        )
        self.assertEqual(
            astro_scan.sanitized_request_headers(headers, include_sensitive=True)["authorization"],
            "Bearer secret",
        )

    def test_decompression(self):
        payload = b"Astro v6.4.5"
        self.assertEqual(astro_scan.decompress_body(gzip.compress(payload), "gzip"), (payload, None))
        self.assertEqual(astro_scan.decompress_body(zlib.compress(payload), "deflate"), (payload, None))
        self.assertEqual(
            astro_scan.decompress_body(gzip.compress(payload), "identity, gzip"),
            (payload, None),
        )
        body, error = astro_scan.decompress_body(payload, "br")
        self.assertEqual(body, payload)
        self.assertIn("unsupported", error)

    def test_image_response_detection(self):
        self.assertTrue(astro_scan.is_image_response({"response_headers": {"content-type": "image/svg+xml"}, "_body": b"<svg></svg>"}))
        self.assertTrue(astro_scan.is_image_response({"response_headers": {}, "_body": b"\x89PNG\r\n"}))
        self.assertFalse(astro_scan.is_image_response({"response_headers": {"content-type": "text/html"}, "_body": b"<html></html>"}))

    def test_resolve_artifact_url_requires_scope(self):
        allowed = ["http://127.0.0.1:4321"]
        self.assertEqual(
            astro_scan.resolve_artifact_url("http://127.0.0.1:4321", "/package.json", allowed),
            "http://127.0.0.1:4321/package.json",
        )
        self.assertEqual(
            astro_scan.resolve_artifact_url("http://127.0.0.1:4321", "http://127.0.0.1:4321/x.map", allowed),
            "http://127.0.0.1:4321/x.map",
        )
        with self.assertRaises(ValueError):
            astro_scan.resolve_artifact_url("http://127.0.0.1:4321", "http://evil.example/x.map", allowed)

    def test_retry_after_seconds(self):
        self.assertEqual(astro_scan.retry_after_seconds({"response_headers": {"retry-after": "2"}}), 2.0)
        self.assertIsNone(astro_scan.retry_after_seconds({"response_headers": {}}))

    def test_module_plan_skips_or_requires_inputs(self):
        args = SimpleNamespace(
            marker=None,
            base_path="/app",
            allow_state_changing_check=False,
            hono_csrf_marker=None,
            remote_pattern_allowed_href=None,
            remote_pattern_bypass_href=None,
            remote_pattern_marker=None,
            i_control_remote_host=False,
            callback_url=None,
            callback_listen=None,
            i_control_callback=False,
            allow_dev_server_check=False,
        )
        modules, skipped = astro_scan.plan_modules(["base-bypass", "encoded-path"], args, strict=False)
        self.assertEqual(modules, [])
        self.assertEqual(len(skipped), 2)
        with self.assertRaises(ValueError):
            astro_scan.plan_modules(["base-bypass"], args, strict=True)
        args.marker = "SECRET"
        modules, skipped = astro_scan.plan_modules(["base-bypass"], args, strict=False)
        self.assertEqual(modules, ["base-bypass"])
        self.assertEqual(skipped, [])

    def test_ssrf_plan_requires_callback_token(self):
        args = SimpleNamespace(
            marker=None,
            base_path="/app",
            allow_state_changing_check=False,
            hono_csrf_marker=None,
            remote_pattern_allowed_href=None,
            remote_pattern_bypass_href=None,
            remote_pattern_marker=None,
            i_control_remote_host=False,
            callback_url="http://callback.example/no-token.svg",
            callback_listen=None,
            i_control_callback=True,
            allow_dev_server_check=False,
        )
        missing = astro_scan.module_missing_inputs("host-header-ssrf", args)
        self.assertIn("--callback-url with astro-callback-<token>.svg", missing)

    def test_profile_selection(self):
        args = SimpleNamespace(modules=None, profile="safe")
        requested, strict = astro_scan.select_requested_modules(args)
        self.assertEqual(requested, ["fingerprint", "sourcemaps"])
        self.assertFalse(strict)
        args = SimpleNamespace(modules="base-bypass", profile=None)
        requested, strict = astro_scan.select_requested_modules(args)
        self.assertEqual(requested, ["fingerprint", "base-bypass"])
        self.assertTrue(strict)
        args = SimpleNamespace(modules="all", profile=None)
        requested, strict = astro_scan.select_requested_modules(args)
        self.assertEqual(set(requested), set(astro_scan.SUPPORTED_MODULES))
        self.assertFalse(strict)

    def test_load_config_normalizes_lists_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "astroscan.toml"
            path.write_text(
                'target = ["http://127.0.0.1:4321"]\n'
                'modules = ["fingerprint", "sourcemaps"]\n'
                'header = ["X-Test: yes"]\n'
                'follow_redirects = false\n'
                f'output_dir = "{directory}/out"\n',
                encoding="utf-8",
            )
            config = astro_scan.load_config(path)
            self.assertEqual(config["target"], ["http://127.0.0.1:4321"])
            self.assertEqual(config["modules"], "fingerprint,sourcemaps")
            self.assertEqual(config["header"], ["X-Test: yes"])
            self.assertFalse(config["follow_redirects"])
            self.assertIsInstance(config["output_dir"], Path)

    def test_verified_callback_events_does_not_wait_without_collector(self):
        events, verified = astro_scan.verified_callback_events(None, "token", 5, set())
        self.assertEqual(events, [])
        self.assertFalse(verified)
        events, verified = astro_scan.verified_callback_events(None, "token", 5, {"token"})
        self.assertTrue(verified)
        self.assertEqual(events[0]["source"], "operator-proof")

    def test_target_slug(self):
        self.assertEqual(astro_scan.target_slug("https://example.com"), "example.com-443")
        self.assertEqual(astro_scan.target_slug("http://127.0.0.1:4321"), "127.0.0.1-4321")

    def test_sarif_report(self):
        report = {
            "target": "https://example.com",
            "overall_status": "vulnerable",
            "findings": [
                {
                    "module": "base-bypass",
                    "identifier": "CVE-2026-84376 / GHSA-376h-93r7-7g6f",
                    "title": "Bypass",
                    "status": "vulnerable",
                    "confidence": "high",
                    "references": ["https://example.com/advisory"],
                }
            ],
        }
        sarif = astro_scan.build_sarif_report([report])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")

    def test_http_client_redirect_gzip_retry_and_redaction(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            retry_count = 0

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
                if self.path == "/gzip":
                    body = gzip.compress(b"compressed")
                    self.send_response(200)
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/retry":
                    type(self).retry_count += 1
                    if type(self).retry_count == 1:
                        self.send_response(503)
                        self.send_header("Retry-After", "0")
                        self.end_headers()
                        return
                    body = b"recovered"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            client = astro_scan.HTTPClient(
                5,
                "test",
                {"Authorization": "Bearer secret", "Cookie": "a=b"},
                delay=0,
                max_retries=1,
                retry_backoff=0,
                allowed_origins=[origin],
            )
            redirected = client.request("GET", origin + "/redirect")
            self.assertEqual(redirected["status"], 200)
            self.assertEqual(len(redirected["redirect_chain"]), 1)
            compressed = client.request("GET", origin + "/gzip")
            self.assertEqual(compressed["_body"], b"compressed")
            Handler.retry_count = 0
            retried = client.request("GET", origin + "/retry")
            self.assertEqual(retried["status"], 200)
            self.assertEqual(retried["attempts"], 2)
            self.assertEqual(client.records[0]["request_headers"]["authorization"], "<redacted>")
            self.assertEqual(client.records[0]["request_headers"]["cookie"], "<redacted>")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_client_budget_record_is_json_serializable(self):
        client = astro_scan.HTTPClient(1, "test", delay=0, max_requests=1, max_retries=0)
        client.request("GET", "http://127.0.0.1:1/")
        client.request("GET", "http://127.0.0.1:1/")
        self.assertTrue(client.budget_exceeded)
        json.dumps(client.records)


if __name__ == "__main__":
    unittest.main()
