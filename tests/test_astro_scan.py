#!/usr/bin/env python3

import unittest
import urllib.parse
import json
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


if __name__ == "__main__":
    unittest.main()
