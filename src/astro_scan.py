#!/usr/bin/env python3
"""Authorized, evidence-oriented scanner for selected Astro vulnerabilities."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import email.utils
import gzip
import hashlib
import html
import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import threading
import time
import tomllib
import unicodedata
import urllib.parse
import uuid
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


VERSION = "1.1.0"

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

ALL_SAFE_MODULES = tuple(
    module for module in SUPPORTED_MODULES if module not in {"dev-error-xss", "hono-csrf"}
)

PROFILES = {
    "safe": ("fingerprint", "sourcemaps"),
    "standard": ALL_SAFE_MODULES,
    "full": SUPPORTED_MODULES,
}

MODULE_REQUIREMENTS = {
    "fingerprint": "none",
    "base-bypass": "--marker and a non-root --base-path",
    "encoded-path": "--marker",
    "transition-xss": "none (optional --transition-path/--transition-param)",
    "transition-directive-xss": "none (optional --transition-directive-path/--transition-directive-param)",
    "spread-attrs-xss": "none (optional --spread-attrs-path/--spread-attrs-param)",
    "custom-element-xss": "none (optional --custom-element-path/--custom-element-param)",
    "hono-csrf": "--allow-state-changing-check and --hono-csrf-marker",
    "remote-pattern-bypass": "--remote-pattern-allowed-href, --remote-pattern-bypass-href, --remote-pattern-marker and --i-control-remote-host",
    "slot-xss": "none (optional --slot-path/--slot-param)",
    "define-vars-xss": "none (optional --define-vars-path/--define-vars-param)",
    "dev-error-xss": "--allow-dev-server-check",
    "sourcemaps": "none (optional --sourcemap-path)",
    "server-island-replay": "none (optional server-island options)",
    "server-island-reflected-xss": "none (optional server-island options)",
    "host-header-ssrf": "--callback-listen or --callback-url with --i-control-callback",
    "image-proxy-ssrf": "--callback-listen or --callback-url with --i-control-callback",
}

SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie",
    "proxy-authenticate",
    "www-authenticate",
}

SENSITIVE_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
}

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
PATH_CONFIG_KEYS = {
    "output",
    "output_dir",
    "target_file",
    "scope_file",
    "header_file",
    "cookie_file",
    "cacert",
    "callback_proof_file",
}
LIST_CONFIG_KEYS = {
    "target",
    "scope",
    "header",
    "cookie",
    "resolve",
    "version_path",
    "sourcemap_path",
    "callback_proof_token",
}
CONFIG_KEYS = {
    "target",
    "target_file",
    "scope",
    "scope_file",
    "allow_remote",
    "authorization_statement",
    "profile",
    "modules",
    "output",
    "output_dir",
    "format",
    "timeout",
    "delay",
    "rate_limit",
    "max_requests",
    "max_retries",
    "retry_backoff",
    "follow_redirects",
    "max_redirects",
    "proxy",
    "insecure",
    "cacert",
    "resolve",
    "header",
    "header_file",
    "cookie",
    "cookie_file",
    "bearer",
    "user_agent",
    "include_sensitive_request_headers",
    "quiet",
    "verbose",
    "fail_on_finding",
    "fail_on_transport_error",
    "fail_on_inconclusive",
    "allow_dev_server_check",
    "callback_url",
    "callback_listen",
    "callback_advertise_host",
    "i_control_callback",
    "callback_timeout",
    "callback_proof_token",
    "callback_proof_file",
    "error_path",
    "image_path",
    "image_format",
    "base_path",
    "protected_path",
    "marker",
    "base_bypass_suffix",
    "single_encoding_depth",
    "deep_encoding_depth",
    "version_path",
    "max_version_artifact_requests",
    "version_probe_default_artifacts",
    "sourcemap_path",
    "max_sourcemap_requests",
    "max_source_map_findings",
    "server_island_path",
    "server_island_param",
    "server_island_source_name",
    "server_island_target_name",
    "server_island_reflected_name",
    "server_island_reflected_slot",
    "hono_csrf_path",
    "hono_csrf_method",
    "hono_csrf_origin",
    "hono_csrf_content_type",
    "hono_csrf_body",
    "hono_csrf_marker",
    "allow_state_changing_check",
    "remote_pattern_path",
    "remote_pattern_allowed_href",
    "remote_pattern_bypass_href",
    "remote_pattern_marker",
    "i_control_remote_host",
    "transition_path",
    "transition_param",
    "transition_directive_path",
    "transition_directive_param",
    "spread_attrs_path",
    "spread_attrs_param",
    "custom_element_path",
    "custom_element_param",
    "slot_path",
    "slot_param",
    "define_vars_path",
    "define_vars_param",
    "trailing_slash_mode",
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


@dataclasses.dataclass
class ScanPlan:
    targets: list[str]
    modules: list[str]
    skipped: list[dict[str, str]]
    scopes: list[str]
    authorization_statement: str
    extra_headers: dict[str, str]
    cookies: str | None
    resolve: dict[tuple[str, int], str]
    proxy: dict[str, Any] | None


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Expected an http(s) origin, received: {value!r}")
    if parsed.username or parsed.password:
        raise ValueError(f"Origins must not contain credentials: {value!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in {value!r}: {exc}") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    port = port if port is not None else default_port
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
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


def read_text_lines(path: Path, label: str) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read {label} {path}: {exc}") from exc


def parse_list_file(path: Path | None, label: str) -> list[str]:
    if path is None:
        return []
    values = []
    for line in read_text_lines(path, label):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


def parse_scope_values(values: list[str] | None, path: Path | None) -> list[str]:
    raw_values = list(values or [])
    raw_values.extend(parse_list_file(path, "scope file"))
    scopes: list[str] = []
    for value in raw_values:
        parsed = urllib.parse.urlsplit(value)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError(f"Scope must be an origin, not a URL with path/query: {value!r}")
        scope = normalize_origin(value)
        if scope not in scopes:
            scopes.append(scope)
    return scopes


def parse_header_values(values: list[str] | None, path: Path | None) -> dict[str, str]:
    raw_values = list(values or [])
    raw_values.extend(parse_list_file(path, "header file"))
    headers: dict[str, str] = {}
    for value in raw_values:
        name, separator, content = value.partition(":")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name) or any(char in content for char in "\r\n"):
            raise ValueError(f"Invalid header {value!r}; expected 'Name: value'")
        headers[name] = content.strip()
    return headers


def parse_cookie_values(values: list[str] | None, path: Path | None) -> str | None:
    raw_values = list(values or [])
    raw_values.extend(parse_list_file(path, "cookie file"))
    cookies = []
    for value in raw_values:
        value = value.strip()
        if value.lower().startswith("cookie:"):
            value = value.split(":", 1)[1].strip()
        if value:
            cookies.append(value)
    return "; ".join(cookies) if cookies else None


def parse_resolve_values(values: list[str] | None) -> dict[tuple[str, int], str]:
    result: dict[tuple[str, int], str] = {}
    for value in values or []:
        match = re.fullmatch(r"\[?([^\]]+)\]?:(\d+):(.+)", value.strip())
        if not match:
            raise ValueError(f"Invalid --resolve {value!r}; expected HOST:PORT:ADDRESS")
        host, port, address = match.group(1).lower(), int(match.group(2)), match.group(3)
        result[(host, port)] = address
    return result


def build_ssl_context(insecure: bool, cacert: Path | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(cacert) if cacert else None)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def parse_proxy(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid proxy URL: {value!r}")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    except ValueError as exc:
        raise ValueError(f"Invalid proxy port in {value!r}: {exc}") from exc
    auth = None
    if parsed.username is not None:
        username = urllib.parse.unquote(parsed.username)
        password = urllib.parse.unquote(parsed.password or "")
        auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"scheme": parsed.scheme, "host": parsed.hostname, "port": port, "auth": auth}


def sanitized_headers(headers: Any) -> dict[str, str]:
    result = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in SENSITIVE_RESPONSE_HEADERS:
            result[normalized] = "<redacted>"
        else:
            result[normalized] = str(value)
    return result


def sanitized_request_headers(headers: dict[str, str], include_sensitive: bool = False) -> dict[str, str]:
    result = {}
    for name, value in headers.items():
        normalized = name.lower()
        if not include_sensitive and normalized in SENSITIVE_REQUEST_HEADERS:
            result[normalized] = "<redacted>"
        else:
            result[normalized] = str(value)
    return result


def decompress_body(body: bytes, content_encoding: str | None) -> tuple[bytes, str | None]:
    if not body or not content_encoding:
        return body, None
    encodings = [encoding.strip().lower() for encoding in content_encoding.split(",") if encoding.strip()]
    for encoding in reversed(encodings):
        try:
            if encoding == "gzip":
                body = gzip.decompress(body)
            elif encoding == "deflate":
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
            elif encoding == "identity":
                continue
            else:
                return body, f"unsupported content-encoding: {encoding}"
        except (OSError, zlib.error) as exc:
            return body, f"{type(exc).__name__}: {exc}"
    return body, None


def retry_after_seconds(record: dict[str, Any]) -> float | None:
    value = record.get("response_headers", {}).get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.UTC)
        return max(0.0, (when - dt.datetime.now(dt.UTC)).total_seconds())
    except (TypeError, ValueError):
        return None


def is_image_response(record: dict[str, Any]) -> bool:
    content_type = record.get("response_headers", {}).get("content-type", "").lower()
    if content_type.startswith("image/"):
        return True
    body = record.get("_body", b"")
    stripped = body.lstrip()
    if stripped.startswith(b"<svg") or (stripped.startswith(b"<?xml") and b"<svg" in stripped[:512]):
        return True
    if body.startswith(b"\x89PNG") or body.startswith(b"\xff\xd8\xff") or body.startswith(b"GIF8"):
        return True
    return body[:4] == b"RIFF" and body[8:12] == b"WEBP"


class ResolvedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, **kwargs: Any) -> None:
        super().__init__(host, port, **kwargs)
        self._resolve_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._resolve_address, self.port), self.timeout, self.source_address
        )


class ResolvedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, **kwargs: Any) -> None:
        super().__init__(host, port, **kwargs)
        self._resolve_address = address

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._resolve_address, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class HTTPClient:
    def __init__(
        self,
        timeout: float,
        user_agent: str,
        extra_headers: dict[str, str] | None = None,
        *,
        delay: float = 0.0,
        rate_limit: float = 0.0,
        max_requests: int = 0,
        max_retries: int = 1,
        retry_backoff: float = 1.0,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        proxy: dict[str, Any] | None = None,
        insecure: bool = False,
        cacert: Path | None = None,
        resolve: dict[tuple[str, int], str] | None = None,
        allowed_origins: list[str] | None = None,
        include_sensitive_request_headers: bool = False,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra_headers = dict(extra_headers or {})
        self.delay = max(0.0, delay)
        self.rate_limit = max(0.0, rate_limit)
        self.max_requests = max_requests
        self.max_retries = max(0, max_retries)
        self.retry_backoff = max(0.0, retry_backoff)
        self.follow_redirects = follow_redirects
        self.max_redirects = max(0, max_redirects)
        self.proxy = proxy
        self.ssl_context = build_ssl_context(insecure, cacert)
        self.resolve = dict(resolve or {})
        self.allowed_origins = set(allowed_origins or [])
        self.include_sensitive_request_headers = include_sensitive_request_headers
        self.verbose = verbose
        self.records: list[dict[str, Any]] = []
        self.transport_errors: list[dict[str, Any]] = []
        self.request_count = 0
        self.budget_exceeded = False
        self._last_request_at = 0.0

    def _wait(self) -> None:
        interval = self.delay
        if self.rate_limit > 0:
            interval = max(interval, 1.0 / self.rate_limit)
        if interval <= 0:
            return
        now = time.monotonic()
        wait = self._last_request_at + interval - now
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _synthetic_error(self, method: str, url: str, message: str) -> dict[str, Any]:
        record = {
            "id": request_id(),
            "timestamp": utc_now(),
            "method": method,
            "url": url,
            "error": message,
            "_body": b"",
        }
        if message == "request budget exceeded":
            record["budget_exceeded"] = True
        self.records.append({key: value for key, value in record.items() if key != "_body"})
        return record

    def _connection(self, parsed: urllib.parse.SplitResult, port: int, path: str) -> tuple[http.client.HTTPConnection, str]:
        host = parsed.hostname or ""
        if self.proxy:
            proxy = self.proxy
            if parsed.scheme == "https":
                if proxy["scheme"] == "https":
                    connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                        proxy["host"], proxy["port"], timeout=self.timeout, context=self.ssl_context
                    )
                else:
                    connection = http.client.HTTPConnection(proxy["host"], proxy["port"], timeout=self.timeout)
                tunnel_headers = {}
                if proxy["auth"]:
                    tunnel_headers["Proxy-Authorization"] = proxy["auth"]
                connection.set_tunnel(host, port, headers=tunnel_headers)
                return connection, path
            if proxy["scheme"] == "https":
                connection = http.client.HTTPSConnection(
                    proxy["host"], proxy["port"], timeout=self.timeout, context=self.ssl_context
                )
            else:
                connection = http.client.HTTPConnection(proxy["host"], proxy["port"], timeout=self.timeout)
            absolute = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
            return connection, absolute
        address = self.resolve.get((host.lower(), port))
        if parsed.scheme == "https":
            if address:
                return ResolvedHTTPSConnection(host, port, address, timeout=self.timeout, context=self.ssl_context), path
            return http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self.ssl_context), path
        if address:
            return ResolvedHTTPConnection(host, port, address, timeout=self.timeout), path
        return http.client.HTTPConnection(host, port, timeout=self.timeout), path

    def _request_once(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return self._synthetic_error(method, url, f"Invalid request URL: {url!r}")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            return self._synthetic_error(method, url, f"Invalid port: {exc}")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            **self.extra_headers,
        }
        if headers:
            connection_headers.update({key: value for key, value in headers.items() if value is not None})
        if self.proxy and self.proxy.get("auth") and parsed.scheme == "http":
            connection_headers.setdefault("Proxy-Authorization", self.proxy["auth"])

        started = time.monotonic()
        started_at = utc_now()
        connection = None
        try:
            connection, request_target = self._connection(parsed, port, path)
            connection.request(method, request_target, body=body, headers=connection_headers)
            response = connection.getresponse()
            raw_body = response.read(1024 * 1024 + 1)
            truncated = len(raw_body) > 1024 * 1024
            if truncated:
                raw_body = raw_body[: 1024 * 1024]
            response_body, decompression_error = decompress_body(
                raw_body, response.getheader("Content-Encoding")
            )
            if len(response_body) > 1024 * 1024:
                response_body = response_body[: 1024 * 1024]
                truncated = True
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            record: dict[str, Any] = {
                "id": request_id(),
                "timestamp": started_at,
                "elapsed_ms": elapsed_ms,
                "method": method,
                "url": url,
                "request_headers": sanitized_request_headers(
                    connection_headers, self.include_sensitive_request_headers
                ),
                "status": response.status,
                "reason": response.reason,
                "response_headers": sanitized_headers(response.headers),
                "body_sha256": sha256_bytes(response_body),
                "body_length": len(response_body),
                "body_truncated": truncated,
                "body_preview": safe_text(response_body),
            }
            if body is not None:
                record["request_body_sha256"] = sha256_bytes(body)
            if decompression_error:
                record["decompression_error"] = decompression_error
            self.records.append(record)
            if self.verbose:
                print(f"[http] {method} {url} -> {response.status}", file=sys.stderr)
            return {**record, "_body": response_body}
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            record = {
                "id": request_id(),
                "timestamp": started_at,
                "elapsed_ms": elapsed_ms,
                "method": method,
                "url": url,
                "request_headers": sanitized_request_headers(
                    connection_headers, self.include_sensitive_request_headers
                ),
                "error": f"{type(exc).__name__}: {exc}",
            }
            self.records.append(record)
            self.transport_errors.append(record)
            if self.verbose:
                print(f"[http] {method} {url} -> ERROR {record['error']}", file=sys.stderr)
            return {**record, "_body": b""}
        finally:
            if connection is not None:
                connection.close()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> dict[str, Any]:
        if self.budget_exceeded:
            return self._synthetic_error(method, url, "request budget exceeded")
        current_url = url
        current_method = method
        redirects: list[dict[str, Any]] = []
        attempts = 0
        while True:
            if self.max_requests and self.request_count >= self.max_requests:
                self.budget_exceeded = True
                return self._synthetic_error(current_method, current_url, "request budget exceeded")
            self._wait()
            self.request_count += 1
            attempts += 1
            record = self._request_once(current_method, current_url, headers, body)
            if record.get("error"):
                if attempts <= self.max_retries:
                    time.sleep(self.retry_backoff * (2 ** (attempts - 1)))
                    continue
                record["attempts"] = attempts
                return record
            status = record.get("status")
            if status in RETRYABLE_STATUSES and attempts <= self.max_retries:
                wait = retry_after_seconds(record) or (self.retry_backoff * (2 ** (attempts - 1)))
                time.sleep(max(0.0, wait))
                continue
            location = record.get("response_headers", {}).get("location")
            if self.follow_redirects and status in REDIRECT_STATUSES and location and current_method in {"GET", "HEAD"}:
                if len(redirects) >= self.max_redirects:
                    record["redirect_error"] = "maximum redirects exceeded"
                    record["attempts"] = attempts
                    return record
                target_url = urllib.parse.urljoin(current_url, location)
                try:
                    target_origin = normalize_origin(target_url)
                except ValueError as exc:
                    record["redirect_error"] = str(exc)
                    record["attempts"] = attempts
                    return record
                if self.allowed_origins and target_origin not in self.allowed_origins:
                    record["redirect_blocked"] = target_origin
                    record["attempts"] = attempts
                    return record
                redirects.append({"from": current_url, "to": target_url, "status": status})
                current_url = target_url
                if status == 303 or status in {301, 302}:
                    current_method = "GET"
                    body = None
                continue
            record["attempts"] = attempts
            if redirects:
                record["redirect_chain"] = redirects
            return record


def canonical_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)
    return path or "/"


def join_origin_path(origin: str, path: str) -> str:
    return origin.rstrip("/") + canonical_path(path)


def resolve_artifact_url(target: str, path: str, allowed_origins: set[str] | list[str]) -> str:
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme in {"http", "https"}:
        origin = normalize_origin(path)
        if origin not in set(allowed_origins):
            raise ValueError(f"Artifact URL {path!r} is outside the authorized origin/scope")
        return path
    if parsed.netloc:
        raise ValueError(f"Artifact path must be relative or an absolute http(s) URL: {path!r}")
    return join_origin_path(target, path)


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
    evidence = marker_evidence(response["_body"], marker)
    return bool(evidence and evidence.get("present"))


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
    baseline_error = baseline.get("error")
    bypass_error = bypass.get("error")
    baseline_blocked = auth_blocked(baseline)
    reached = protected_reached(bypass, marker)
    if baseline_error or bypass_error:
        status = "inconclusive"
        confidence = "low"
    elif baseline_blocked and reached:
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
            "baseline_error": baseline_error,
            "bypass_request_id": bypass["id"],
            "bypass_path": urllib.parse.urlsplit(bypass["url"]).path,
            "bypass_status": bypass.get("status", bypass.get("error")),
            "bypass_error": bypass_error,
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
    high_confidence = bool(
        version_evidence
        and any(
            item["source"] in exact_sources or item["source"].startswith("http-header:")
            for item in version_evidence
        )
    )
    if response.get("error"):
        status = "inconclusive"
        confidence = "low"
    else:
        status = "astro-version-identified" if version else ("astro-candidate" if signals else "no-astro-signal")
        confidence = "high" if high_confidence else ("medium" if version else "low")
    return Finding(
        module="fingerprint",
        identifier="ASTRO-FINGERPRINT",
        title="Astro surface fingerprint",
        status=status,
        confidence=confidence,
        evidence={
            "request_id": response["id"],
            "status": response.get("status", response.get("error")),
            "response_error": response.get("error"),
            "signals": signals,
            "astro_version": version,
            "version_evidence": version_evidence,
            "note": "A version is reported only from exact exposed metadata or build artifact; behavioral signals alone remain non-proof.",
        },
        remediation="Confirm inventory ownership for final reporting and remove public package, lock, or source-map artifacts that disclose the build version.",
        references=["https://docs.astro.build/en/recipes/upgrade-astro/"],
        limitations=["Astro sites commonly omit version metadata; absence of a version is not evidence of a fixed or vulnerable release."],
    )


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
        response = client.request("GET", resolve_artifact_url(target, path, client.allowed_origins))
        requests_made += 1
        if response.get("status") != 200:
            continue
        path_name = urllib.parse.urlsplit(path).path
        for item in extract_astro_versions(response.get("_body", b""), response.get("response_headers", {}), path_name):
            if item not in results:
                results.append(item)
    for path in map_candidates[: max(0, args.max_version_artifact_requests - requests_made)]:
        response = client.request("GET", resolve_artifact_url(target, path, client.allowed_origins))
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
    if response.get("error"):
        injection = {"present": False, "error": response["error"]}
        status = "inconclusive"
        confidence = "low"
    else:
        injection = raw_html_injection_evidence(response.get("_body", b""), token)
        vulnerable = injection["present"]
        status = "vulnerable" if vulnerable else "not-vulnerable-or-not-applicable"
        confidence = "high" if vulnerable else "medium"
    return Finding(
        module=module,
        identifier=identifier,
        title=title,
        status=status,
        confidence=confidence,
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "response_error": response.get("error"),
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
    if response.get("error"):
        status = "inconclusive"
        confidence = "low"
        marker_present = False
    else:
        body = response.get("_body", b"").decode("utf-8", errors="replace")
        marker_present = args.hono_csrf_marker in body
        vulnerable = response.get("status") == 200 and marker_present
        status = "vulnerable" if vulnerable else "not-vulnerable-or-not-applicable"
        confidence = "high" if vulnerable else "medium"
    return Finding(
        module="hono-csrf",
        identifier="CVE-2026-73423 / GHSA-8mv7-9c27-98vc",
        title="Astro Hono pipeline cross-origin state change",
        status=status,
        confidence=confidence,
        evidence={
            "request_id": response["id"],
            "request_method": args.hono_csrf_method,
            "request_path": canonical_path(args.hono_csrf_path),
            "cross_origin_header": args.hono_csrf_origin,
            "form_like_content_type": args.hono_csrf_content_type,
            "response_status": response.get("status", response.get("error")),
            "response_error": response.get("error"),
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
    bypass = client.request("GET", remote_pattern_url(target, args.remote_pattern_path, args.remote_pattern_bypass_href))

    def marker_evidence(response: dict[str, Any]) -> dict[str, Any]:
        body = response.get("_body", b"")
        return {
            "status": response.get("status", response.get("error")),
            "error": response.get("error"),
            "marker_present": args.remote_pattern_marker.encode("utf-8") in body,
            "image_response": is_image_response(response),
            "content_type": response.get("response_headers", {}).get("content-type"),
            "request_id": response["id"],
            "response_context": safe_text(body, 384),
        }

    allowed_evidence = marker_evidence(allowed)
    bypass_evidence = marker_evidence(bypass)
    allowed_works = allowed_evidence["status"] == 200 and allowed_evidence["marker_present"]
    bypass_works = bypass_evidence["status"] == 200 and bypass_evidence["marker_present"]
    if allowed.get("error") or bypass.get("error"):
        status = "inconclusive"
        confidence = "low"
    elif allowed_works and bypass_works and allowed_evidence["image_response"] and bypass_evidence["image_response"]:
        status = "vulnerable"
        confidence = "high"
    elif allowed_works and bypass_works:
        status = "inconclusive"
        confidence = "low"
    elif not allowed_works:
        status = "inconclusive"
        confidence = "low"
    else:
        status = "not-vulnerable-or-not-applicable"
        confidence = "medium"
    return Finding(
        module="remote-pattern-bypass",
        identifier="CVE-2026-33769 / GHSA-g735-7g2w-hh3f",
        title="Astro remotePatterns wildcard path bypass",
        status=status,
        confidence=confidence,
        evidence={
            "allowed_control": allowed_evidence,
            "bypass_attempt": bypass_evidence,
            "allowed_href": args.remote_pattern_allowed_href,
            "bypass_href": args.remote_pattern_bypass_href,
            "proof_boundary": "Both operator-controlled URLs must return image content containing the marker; a reflected href in an HTML error page is not fetch evidence.",
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
    candidates = []
    for path in explicit_paths:
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme in {"http", "https"}:
            candidates.append(path)
        else:
            candidates.append(canonical_path(path))
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
        response = client.request("GET", resolve_artifact_url(target, path, client.allowed_origins))
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
    if homepage.get("error"):
        status = "inconclusive"
        confidence = "low"
    elif valid:
        status = "vulnerable"
        confidence = "high"
    else:
        status = "not-vulnerable-or-not-applicable"
        confidence = "low"
    return Finding(
        module="sourcemaps",
        identifier="CVE-2024-56159 / GHSA-49w6-73cw-chjr",
        title="Astro server source maps exposed",
        status=status,
        confidence=confidence,
        evidence={
            "homepage_request_id": homepage["id"],
            "homepage_error": homepage.get("error"),
            "tested_paths": candidates,
            "valid_source_maps": valid,
        },
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
    if page.get("error"):
        return Finding(
            module="server-island-replay",
            identifier="CVE-2026-45028 / GHSA-xr5h-phrj-8vxv",
            title="Astro server island cross-component parameter replay",
            status="inconclusive",
            confidence="low",
            evidence={
                "page_request_id": page["id"],
                "page_status": page.get("status", page.get("error")),
                "page_error": page.get("error"),
                "source_component": args.server_island_source_name,
                "target_component": args.server_island_target_name,
                "reason": "The page request failed",
            },
            remediation="Upgrade Astro to 6.1.10 or later and audit overlapping prop/slot names across server islands.",
            references=["https://github.com/withastro/astro/security/advisories/GHSA-xr5h-phrj-8vxv"],
            limitations=["The application must expose two server islands with the same prop/slot name and attacker-controlled source prop."],
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
    if replay.get("error"):
        status = "inconclusive"
        confidence = "low"
        vulnerable = False
    else:
        vulnerable = bool(replay_evidence.get("present") and replay_evidence.get("html_context") == "raw")
        status = "vulnerable" if vulnerable else "not-vulnerable-or-not-applicable"
        confidence = "high" if vulnerable else "low"
    return Finding(
        module="server-island-replay",
        identifier="CVE-2026-45028 / GHSA-xr5h-phrj-8vxv",
        title="Astro server island cross-component parameter replay",
        status=status,
        confidence=confidence,
        evidence={
            "page_request_id": page["id"],
            "page_status": page.get("status", page.get("error")),
            "replay_request_id": replay["id"],
            "replay_status": replay.get("status", replay.get("error")),
            "replay_error": replay.get("error"),
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


def wait_for_callback(
    collector: CallbackCollector | None,
    token: str | None,
    timeout: float,
    *,
    since_index: int = 0,
    require_token_in_path: bool = True,
) -> list[dict[str, Any]]:
    if collector is None:
        return []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = collector.events[since_index:]
        events = [
            event
            for event in candidates
            if not require_token_in_path or (token and token in event["path"])
        ]
        if events:
            return events
        time.sleep(0.1)
    return []


def callback_proof_tokens(args: argparse.Namespace) -> set[str]:
    tokens = set(args.callback_proof_token or [])
    tokens.update(parse_list_file(args.callback_proof_file, "callback proof file"))
    return tokens


def verified_callback_events(
    collector: CallbackCollector | None,
    token: str | None,
    timeout: float,
    proof_tokens: set[str],
    *,
    since_index: int = 0,
    require_token_in_path: bool = True,
) -> tuple[list[dict[str, Any]], bool]:
    events = wait_for_callback(
        collector,
        token,
        timeout,
        since_index=since_index,
        require_token_in_path=require_token_in_path,
    )
    if events:
        return events, True
    if token and token in proof_tokens:
        return [
            {
                "source": "operator-proof",
                "proof": "callback token present in --callback-proof-token/--callback-proof-file",
            }
        ], True
    return [], False


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
    start_index = len(collector.events) if collector else 0
    response = client.request(
        "GET",
        join_origin_path(target, args.error_path),
        headers={"Host": callback_netloc, "X-Astro-Scan": "host-header-ssrf"},
    )
    events, verified = verified_callback_events(
        collector,
        token,
        args.callback_timeout,
        callback_proof_tokens(args),
        since_index=start_index,
        require_token_in_path=False,
    )
    reflected = bool(token and token in response.get("_body", b"").decode("utf-8", errors="replace"))
    if response.get("error") and not verified:
        status = "inconclusive"
        confidence = "low"
    elif verified and reflected:
        status = "vulnerable"
        confidence = "high"
    elif verified:
        status = "callback-observed"
        confidence = "medium"
    elif reflected:
        status = "inconclusive"
        confidence = "low"
    else:
        status = "not-vulnerable-or-not-applicable"
        confidence = "low"
    return Finding(
        module="host-header-ssrf",
        identifier="CVE-2026-54299 / GHSA-2pvr-wf23-7pc7",
        title="Astro prerendered error page Host-header SSRF",
        status=status,
        confidence=confidence,
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "response_error": response.get("error"),
            "attacker_host": callback_netloc,
            "callback_events": events,
            "callback_verified": verified,
            "callback_response_reflected": reflected,
            "proof_boundary": "A positive requires a verified callback to the operator-controlled host plus reflection of its unique token; reflection alone is not fetch evidence.",
        },
        remediation="Upgrade Astro and the Node adapter to fixed versions, validate Host against allowedDomains, and override prerenderedErrorPageFetch safely.",
        references=["https://github.com/withastro/astro/security/advisories/GHSA-2pvr-wf23-7pc7"],
        limitations=[
            "Uses only the operator-controlled callback host; it does not probe internal addresses.",
            "An external --callback-url requires --callback-proof-token or --callback-proof-file; without it the result is inconclusive.",
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
    start_index = len(collector.events) if collector else 0
    response = client.request("GET", request_url)
    events, verified = verified_callback_events(
        collector,
        token,
        args.callback_timeout,
        callback_proof_tokens(args),
        since_index=start_index,
    )
    body = response.get("_body", b"").decode("utf-8", errors="replace")
    callback_token_returned = bool(token and token in body)
    if verified:
        status = "vulnerable"
        confidence = "high"
    elif callback_token_returned:
        status = "inconclusive"
        confidence = "low"
    elif response.get("error"):
        status = "inconclusive"
        confidence = "low"
    else:
        status = "not-vulnerable-or-not-applicable"
        confidence = "medium"
    return Finding(
        module="image-proxy-ssrf",
        identifier="CVE-2025-59837 / GHSA-qcpr-679q-rhm2",
        title="Astro image proxy domain-validation bypass",
        status=status,
        confidence=confidence,
        evidence={
            "request_id": response["id"],
            "response_status": response.get("status", response.get("error")),
            "response_error": response.get("error"),
            "href_scheme_bypass": "backslash",
            "callback_events": events,
            "callback_verified": verified,
            "callback_token_returned": callback_token_returned,
            "response_context": safe_text(response.get("_body", b""), 384),
            "proof_boundary": "A positive requires a verified request to the operator-controlled callback host; a token reflected in the response without a callback is inconclusive.",
        },
        remediation="Upgrade Astro to a release containing both image-domain validation fixes and reject backslash-based URL forms.",
        references=["https://github.com/withastro/astro/security/advisories/GHSA-qcpr-679q-rhm2"],
        limitations=[
            "Proves a controlled outbound request only; internal-network impact requires separate explicit authorization and testing.",
            "An external --callback-url requires --callback-proof-token or --callback-proof-file; without it the result is inconclusive.",
        ],
    )


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Cannot read config {path}: {exc}") from exc
    if isinstance(data.get("astroscan"), dict):
        data = data["astroscan"]
    result: dict[str, Any] = {}
    for key, value in data.items():
        normalized = key.replace("-", "_")
        if normalized not in CONFIG_KEYS:
            print(f"astro_scan: ignoring unknown config key {key!r}", file=sys.stderr)
            continue
        if normalized in PATH_CONFIG_KEYS and value is not None:
            value = Path(value)
        if normalized in LIST_CONFIG_KEYS:
            if isinstance(value, str):
                value = [value]
            elif isinstance(value, list):
                value = [str(item) for item in value]
        if normalized == "modules" and isinstance(value, list):
            value = ",".join(str(item) for item in value)
        result[normalized] = value
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    argv = sys.argv[1:] if argv is None else argv
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", type=Path)
    known, _ = pre_parser.parse_known_args(argv)
    config_defaults = load_config(known.config)
    if any(argument == "--target" or argument.startswith("--target=") for argument in argv):
        config_defaults.pop("target", None)

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", type=Path, help="TOML config file with defaults")
    parser.add_argument("--version", action="store_true", help="Print the scanner version and exit")
    parser.add_argument("--list-modules", action="store_true", help="List modules and their required inputs")
    parser.add_argument("--target", action="append", help="Exact target origin; repeatable")
    parser.add_argument("--target-file", type=Path, help="File with one target origin per line")
    parser.add_argument("--scope", action="append", default=[], help="Authorized origin; repeatable")
    parser.add_argument("--scope-file", type=Path, help="File with one authorized origin per line")
    parser.add_argument("--allow-remote", action="store_true", help="Acknowledge that non-local targets are in scope")
    parser.add_argument("--authorization-statement", help="Traceable program/ticket authorization statement; @file is supported")
    parser.add_argument("--profile", choices=tuple(PROFILES), help="Module preset: safe, standard or full")
    parser.add_argument("--modules", help=f"Comma-separated modules: {','.join(SUPPORTED_MODULES)},all,all-safe")
    parser.add_argument("--dry-run", action="store_true", help="Print the execution plan and exit without network requests")
    parser.add_argument("--output", type=Path, help="Write the JSON evidence bundle to this path (single target)")
    parser.add_argument("--output-dir", type=Path, help="Write one JSON evidence file per target and a summary")
    parser.add_argument("--format", choices=("human", "json", "jsonl", "sarif"), default="human", help="Terminal output format")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--delay", type=float, default=0.25, help="Minimum delay between requests in seconds")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Maximum requests per second (0 = disabled)")
    parser.add_argument("--max-requests", type=int, default=0, help="Global request budget (0 = unlimited)")
    parser.add_argument("--max-retries", type=int, default=1, help="Retries for transport errors and 429/5xx")
    parser.add_argument("--retry-backoff", type=float, default=1.0, help="Base exponential backoff in seconds")
    parser.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction, default=True, help="Follow same-origin/scope redirects")
    parser.add_argument("--max-redirects", type=int, default=5)
    parser.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=False, help="Disable TLS certificate verification")
    parser.add_argument("--cacert", type=Path, help="Custom CA bundle")
    parser.add_argument("--resolve", action="append", default=[], help="HOST:PORT:ADDRESS resolver override; repeatable")
    parser.add_argument("--header", action="append", default=[], help="Extra 'Name: value' header; repeatable")
    parser.add_argument("--header-file", type=Path, help="File with 'Name: value' headers")
    parser.add_argument("--cookie", action="append", default=[], help="Cookie 'name=value'; repeatable")
    parser.add_argument("--cookie-file", type=Path, help="File with cookie 'name=value' lines")
    parser.add_argument("--bearer", help="Authorization: Bearer token")
    parser.add_argument("--include-sensitive-request-headers", action="store_true", help="Store Authorization/Cookie values in evidence")
    parser.add_argument("--user-agent", default=f"AstroScan/{VERSION} (authorized-security-test)")
    parser.add_argument("--quiet", action="store_true", help="Suppress the full human report")
    parser.add_argument("--verbose", action="store_true", help="Print every HTTP transaction to stderr")
    parser.add_argument("--fail-on-finding", action="store_true")
    parser.add_argument("--fail-on-transport-error", action="store_true")
    parser.add_argument("--fail-on-inconclusive", action="store_true")
    parser.add_argument("--allow-dev-server-check", action="store_true", help="Allow dev-error-xss against an exposed development server")
    parser.add_argument("--allow-state-changing-check", action="store_true", help="Allow the hono-csrf state-changing request")

    base = parser.add_argument_group("base-path bypass")
    base.add_argument("--base-path", default="/app")
    base.add_argument("--protected-path", default="/admin")
    base.add_argument("--marker", help="String that proves protected content was returned")
    base.add_argument("--base-bypass-suffix", default="X")

    version = parser.add_argument_group("Astro version fingerprint")
    version.add_argument("--version-path", action="append", default=[], help="Additional version-bearing path or same-scope URL; repeatable")
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
    ssrf.add_argument("--callback-proof-token", action="append", default=[], help="Operator-confirmed callback token for an external callback; repeatable")
    ssrf.add_argument("--callback-proof-file", type=Path, help="File with operator-confirmed callback tokens")
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
    xss.add_argument("--slot-path", default="/")
    xss.add_argument("--slot-param", default="tab")
    xss.add_argument("--define-vars-path", default="/")
    xss.add_argument("--define-vars-param", default="name")
    xss.add_argument("--trailing-slash-mode", choices=("never", "always"), default="never")

    hono = parser.add_argument_group("astro/hono CSRF")
    hono.add_argument("--hono-csrf-path", default="/api/delete")
    hono.add_argument("--hono-csrf-method", choices=("POST", "PUT", "PATCH", "DELETE"), default="POST")
    hono.add_argument("--hono-csrf-origin", default="http://astro-scan-cross-origin.invalid")
    hono.add_argument("--hono-csrf-content-type", default="application/x-www-form-urlencoded")
    hono.add_argument("--hono-csrf-body", default="astro-scan-csrf-proof=1")
    hono.add_argument("--hono-csrf-marker", help="Exact harmless response marker proving handler execution")

    remote_pattern = parser.add_argument_group("remotePatterns bypass")
    remote_pattern.add_argument("--remote-pattern-path", default="/_image")
    remote_pattern.add_argument("--remote-pattern-allowed-href")
    remote_pattern.add_argument("--remote-pattern-bypass-href")
    remote_pattern.add_argument("--remote-pattern-marker")
    remote_pattern.add_argument("--i-control-remote-host", action="store_true")

    parser.set_defaults(**config_defaults)
    return parser.parse_args(argv)


def module_missing_inputs(module: str, args: argparse.Namespace) -> list[str]:
    missing: list[str] = []
    if module in {"base-bypass", "encoded-path"} and not args.marker:
        missing.append("--marker")
    if module == "base-bypass" and canonical_path(args.base_path) == "/":
        missing.append("--base-path (non-root)")
    if module == "hono-csrf":
        if not args.allow_state_changing_check:
            missing.append("--allow-state-changing-check")
        if not args.hono_csrf_marker:
            missing.append("--hono-csrf-marker")
    if module == "remote-pattern-bypass":
        if not args.remote_pattern_allowed_href:
            missing.append("--remote-pattern-allowed-href")
        if not args.remote_pattern_bypass_href:
            missing.append("--remote-pattern-bypass-href")
        if not args.remote_pattern_marker:
            missing.append("--remote-pattern-marker")
        if not args.i_control_remote_host:
            missing.append("--i-control-remote-host")
    if module in {"host-header-ssrf", "image-proxy-ssrf"}:
        if not (args.callback_url or args.callback_listen):
            missing.append("--callback-listen or --callback-url")
        if not args.i_control_callback:
            missing.append("--i-control-callback")
        if args.callback_url and not callback_token(args.callback_url):
            missing.append("--callback-url with astro-callback-<token>.svg")
    if module == "dev-error-xss" and not args.allow_dev_server_check:
        missing.append("--allow-dev-server-check")
    return missing


def select_requested_modules(args: argparse.Namespace) -> tuple[list[str], bool]:
    raw = args.modules
    strict = False
    if raw:
        values = [value.strip() for value in raw.split(",") if value.strip()]
        strict = not any(value in {"all", "all-safe"} for value in values)
    elif args.profile:
        values = list(PROFILES[args.profile])
    else:
        values = ["fingerprint"]
    if "all" in values:
        values = list(SUPPORTED_MODULES)
    elif "all-safe" in values:
        values = list(ALL_SAFE_MODULES)
    unknown = set(values) - set(SUPPORTED_MODULES)
    if unknown:
        raise ValueError(f"Unknown modules: {sorted(unknown)}")
    requested: list[str] = []
    for module in values:
        if module not in requested:
            requested.append(module)
    if "fingerprint" not in requested:
        requested.insert(0, "fingerprint")
    return requested, strict


def plan_modules(requested: list[str], args: argparse.Namespace, strict: bool) -> tuple[list[str], list[dict[str, str]]]:
    modules: list[str] = []
    skipped: list[dict[str, str]] = []
    for module in requested:
        missing = module_missing_inputs(module, args)
        if missing:
            reason = "missing " + ", ".join(missing)
            if strict:
                raise ValueError(f"{module} requires {', '.join(missing)}")
            skipped.append({"module": module, "reason": reason})
            continue
        modules.append(module)
    return modules, skipped


def validate_args(args: argparse.Namespace) -> ScanPlan:
    if args.delay < 0:
        raise ValueError("--delay cannot be negative")
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    if args.rate_limit < 0:
        raise ValueError("--rate-limit cannot be negative")
    if args.max_requests < 0:
        raise ValueError("--max-requests cannot be negative")
    if args.max_retries < 0:
        raise ValueError("--max-retries cannot be negative")
    if args.retry_backoff < 0:
        raise ValueError("--retry-backoff cannot be negative")
    if args.max_redirects < 0:
        raise ValueError("--max-redirects cannot be negative")
    if args.single_encoding_depth < 1:
        raise ValueError("--single-encoding-depth must be at least 1")
    if args.deep_encoding_depth < 1:
        raise ValueError("--deep-encoding-depth must be at least 1")
    if args.max_version_artifact_requests < 0:
        raise ValueError("--max-version-artifact-requests cannot be negative")
    if args.max_sourcemap_requests < 0:
        raise ValueError("--max-sourcemap-requests cannot be negative")
    if args.max_source_map_findings < 0:
        raise ValueError("--max-source-map-findings cannot be negative")
    if args.base_bypass_suffix and "/" in args.base_bypass_suffix:
        raise ValueError("--base-bypass-suffix must be a path-segment string without '/'")
    if args.cacert and not args.cacert.exists():
        raise ValueError(f"--cacert does not exist: {args.cacert}")
    if args.output and args.output_dir:
        raise ValueError("Use --output or --output-dir, not both")

    raw_targets: list[str] = []
    if args.target:
        raw_targets.extend([args.target] if isinstance(args.target, str) else args.target)
    raw_targets.extend(parse_list_file(args.target_file, "target file"))
    if not raw_targets:
        raise ValueError("--target or --target-file is required")
    targets: list[str] = []
    for raw in raw_targets:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError(
                f"Target must be an origin, not a URL with path/query: {raw!r}; "
                "use --base-path/--protected-path for application paths"
            )
        target = normalize_origin(raw)
        if target not in targets:
            targets.append(target)

    scopes = parse_scope_values(args.scope, args.scope_file)
    authorization_statement = args.authorization_statement
    if authorization_statement and authorization_statement.startswith("@"):
        authorization_statement = Path(authorization_statement[1:]).read_text(encoding="utf-8").strip()

    for target in targets:
        parsed = urllib.parse.urlsplit(target)
        local = is_local_hostname(parsed.hostname or "")
        if not local:
            missing = []
            if not args.allow_remote:
                missing.append("--allow-remote")
            if not scopes:
                missing.append("--scope <authorized-origin> or --scope-file")
            if not authorization_statement or len(authorization_statement.strip()) < 12:
                missing.append("--authorization-statement")
            if missing:
                raise ValueError("Remote testing refused; provide: " + ", ".join(missing))
        if scopes and target not in scopes:
            raise ValueError(f"Target {target} is not exactly listed in --scope")

    extra_headers = parse_header_values(args.header, args.header_file)
    cookies = parse_cookie_values(args.cookie, args.cookie_file)
    if cookies:
        extra_headers["Cookie"] = cookies
    if args.bearer:
        extra_headers.setdefault("Authorization", f"Bearer {args.bearer}")
    resolve = parse_resolve_values(args.resolve)
    proxy = parse_proxy(args.proxy)
    validate_callback(args.callback_url, args.i_control_callback)
    if args.callback_listen and not args.i_control_callback:
        raise ValueError("--callback-listen requires --i-control-callback")
    if args.callback_listen and args.callback_url:
        raise ValueError("Use either --callback-listen or --callback-url, not both")
    if args.callback_timeout < 0:
        raise ValueError("--callback-timeout cannot be negative")

    requested, strict = select_requested_modules(args)
    modules, skipped = plan_modules(requested, args, strict)
    if args.output and len(targets) > 1:
        raise ValueError("--output supports one target; use --output-dir for multiple targets")
    return ScanPlan(
        targets=targets,
        modules=modules,
        skipped=skipped,
        scopes=scopes,
        authorization_statement=authorization_statement or "",
        extra_headers=extra_headers,
        cookies=cookies,
        resolve=resolve,
        proxy=proxy,
    )


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


def human_label(status: str) -> str:
    if status == "vulnerable":
        return "VULNERABLE"
    if status == "inconclusive":
        return "INCONCLUSIVE"
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
            "callback_token_returned", "callback_response_reflected", "callback_verified",
            "baseline_status", "bypass_status", "protected_marker_present", "response_status",
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
    skipped = report.get("skipped_modules", [])
    if skipped:
        lines.append("Skipped modules")
        lines.append("---------------")
        for item in skipped:
            lines.append(f"  {item['module']}: {item['reason']}")
        lines.append("")
    lines.extend((
        f"Transport errors: {len(report.get('transport_errors', []))}",
        f"Request budget exceeded: {'yes' if report.get('budget_exceeded') else 'no'}",
        f"Overall: {report['overall_status'].replace('-', ' ').upper()}",
        f"Modules executed: {len(report['findings'])}",
        f"HTTP transactions: {len(report.get('http_transactions', []))}",
        f"Evidence file: {report.get('output_file') or 'not written'}",
    ))
    return "\n".join(lines) + "\n"


def build_sarif_report(reports: list[dict[str, Any]]) -> dict[str, Any]:
    runs = []
    for report in reports:
        rules = []
        results = []
        seen_rules = set()
        for finding in report["findings"]:
            if finding["status"] not in {"vulnerable", "inconclusive", "callback-observed"}:
                continue
            rule_id = finding.get("identifier") or finding["module"]
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": finding["module"],
                    "shortDescription": {"text": finding["title"]},
                    "helpUri": (finding.get("references") or [""])[0],
                })
            results.append({
                "ruleId": rule_id,
                "level": "error" if finding["status"] == "vulnerable" else "warning",
                "message": {"text": f"{finding['title']}: {finding['status']} ({finding['confidence']} confidence)"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report["target"]},
                    }
                }],
                "properties": {"status": finding["status"], "module": finding["module"]},
            })
        runs.append({
            "tool": {"driver": {"name": "AstroScan", "version": VERSION, "rules": rules}},
            "results": results,
            "properties": {"target": report["target"], "overall_status": report["overall_status"]},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }


def render_plan(plan: ScanPlan, args: argparse.Namespace) -> str:
    lines = [
        "AstroScan plan",
        "==============",
        f"Targets: {', '.join(plan.targets)}",
        f"Scopes: {', '.join(plan.scopes) if plan.scopes else 'loopback only'}",
        f"Authorization statement: {'provided' if plan.authorization_statement else 'not required'}",
        f"Modules: {', '.join(plan.modules)}",
        f"Request delay: {args.delay}s",
        f"Rate limit: {args.rate_limit or 'disabled'}",
        f"Max requests: {args.max_requests or 'unlimited'}",
        f"Follow redirects: {'yes' if args.follow_redirects else 'no'} (max {args.max_redirects})",
        f"Proxy: {'configured' if plan.proxy else 'none'}",
        f"TLS verification: {'disabled' if args.insecure else 'enabled'}",
        f"Output: {args.output or args.output_dir or 'stdout only'}",
    ]
    if plan.skipped:
        lines.append("Skipped modules:")
        for item in plan.skipped:
            lines.append(f"  {item['module']}: {item['reason']}")
    else:
        lines.append("Skipped modules: none")
    return "\n".join(lines) + "\n"


def print_module_list() -> None:
    print("Module | Required inputs")
    print("------ | ---------------")
    for module in SUPPORTED_MODULES:
        print(f"{module} | {MODULE_REQUIREMENTS[module]}")
    print("")
    print("Profiles:")
    for name, modules in PROFILES.items():
        print(f"  {name}: {', '.join(modules)}")
    print("  all-safe: all modules except dev-error-xss and hono-csrf")
    print("  all: every module")


def module_finding(module: str, target: str, args: argparse.Namespace, plan: ScanPlan, client: HTTPClient, callback_url: str | None, callback_server: CallbackServer | None) -> list[Finding]:
    if module == "base-bypass":
        return [run_base_bypass(client, target, args)]
    if module == "encoded-path":
        return run_encoded_path(client, target, args)
    if module == "transition-xss":
        return [run_transition_xss(client, target, args)]
    if module == "transition-directive-xss":
        return [run_transition_directive_xss(client, target, args)]
    if module == "spread-attrs-xss":
        return [run_spread_attrs_xss(client, target, args)]
    if module == "custom-element-xss":
        return [run_custom_element_xss(client, target, args)]
    if module == "hono-csrf":
        return [run_hono_csrf(client, target, args)]
    if module == "remote-pattern-bypass":
        return [run_remote_pattern_bypass(client, target, args)]
    if module == "slot-xss":
        return [run_slot_xss(client, target, args)]
    if module == "define-vars-xss":
        return [run_define_vars_xss(client, target, args)]
    if module == "dev-error-xss":
        return [run_dev_error_xss(client, target, args)]
    if module == "sourcemaps":
        return [run_sourcemaps(client, target, args)]
    if module == "server-island-replay":
        return [run_server_island_replay(client, target, args)]
    if module == "server-island-reflected-xss":
        return [run_server_island_reflected_xss(client, target, args)]
    if module == "host-header-ssrf" and callback_url:
        return [run_host_header_ssrf(client, target, args, callback_url, callback_server.collector if callback_server else None)]
    if module == "image-proxy-ssrf" and callback_url:
        return [run_image_proxy_ssrf(client, target, args, callback_url, callback_server.collector if callback_server else None)]
    return []


def run_target(target: str, plan: ScanPlan, args: argparse.Namespace) -> dict[str, Any]:
    callback_server = None
    callback_url = None
    findings: list[Finding] = []
    client = None
    try:
        needs_callback = bool({"host-header-ssrf", "image-proxy-ssrf"} & set(plan.modules))
        callback_server, callback_url = start_callback(args) if needs_callback else (None, None)
        client = HTTPClient(
            timeout=args.timeout,
            user_agent=args.user_agent,
            extra_headers=plan.extra_headers,
            delay=args.delay,
            rate_limit=args.rate_limit,
            max_requests=args.max_requests,
            max_retries=args.max_retries,
            retry_backoff=args.retry_backoff,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            proxy=plan.proxy,
            insecure=args.insecure,
            cacert=args.cacert,
            resolve=plan.resolve,
            allowed_origins=[target] + plan.scopes,
            include_sensitive_request_headers=args.include_sensitive_request_headers,
            verbose=args.verbose,
        )
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
        if args.format == "human" and not args.quiet:
            print(
                f"AstroScan preflight: {target}; exact version={version or 'not identified'}; "
                f"version-matched advisories={version_assessment['matched_count']}",
                flush=True,
            )
        for module in plan.modules:
            if module == "fingerprint":
                continue
            try:
                findings.extend(module_finding(module, target, args, plan, client, callback_url, callback_server))
            except Exception as exc:
                findings.append(
                    Finding(
                        module=module,
                        identifier="",
                        title="Module execution error",
                        status="inconclusive",
                        confidence="low",
                        evidence={"error": f"{type(exc).__name__}: {exc}"},
                        remediation="Review the module inputs and transport configuration, then retry.",
                        references=[],
                        limitations=["The module did not complete; this is not a negative result."],
                    )
                )
        parsed_target = urllib.parse.urlsplit(target)
        if any(finding.status == "vulnerable" for finding in findings):
            overall_status = "vulnerable"
        elif any(finding.status == "inconclusive" for finding in findings):
            overall_status = "inconclusive"
        else:
            overall_status = "no-confirmed-finding"
        report = {
            "schema": "astro-scan-evidence/1",
            "generated_at": utc_now(),
            "scanner": f"AstroScan {VERSION}",
            "target": target,
            "target_local": is_local_hostname(parsed_target.hostname or ""),
            "authorization": {
                "scope": plan.scopes,
                "authorization_statement": plan.authorization_statement,
                "remote_testing_allowed": args.allow_remote,
                "policy": "Exact-origin authorization is required for non-loopback targets; SSRF checks use only an operator-controlled callback.",
            },
            "configuration": {
                "profile": args.profile,
                "modules": plan.modules,
                "skipped_modules": plan.skipped,
                "timeout_seconds": args.timeout,
                "delay_seconds": args.delay,
                "rate_limit": args.rate_limit,
                "max_requests": args.max_requests,
                "max_retries": args.max_retries,
                "follow_redirects": args.follow_redirects,
                "proxy": bool(plan.proxy),
                "tls_verification": not args.insecure,
                "marker_supplied": bool(args.marker),
                "extra_headers": sorted(plan.extra_headers),
                "request_headers_redacted": not args.include_sensitive_request_headers,
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
            "skipped_modules": plan.skipped,
            "transport_errors": [
                {"id": record["id"], "url": record["url"], "error": record["error"]}
                for record in client.transport_errors
            ],
            "budget_exceeded": client.budget_exceeded,
            "http_transactions": client.records,
            "overall_status": overall_status,
            "limitations": [
                "Astro fingerprinting is not version identification.",
                "Positive authorization-bypass evidence requires a supplied protected-content marker.",
                "SSRF modules do not probe internal services or use third-party callback hosts.",
                "CVE-2026-84383 memory-corruption input is intentionally not sent to remote targets.",
            ],
        }
        return report
    finally:
        if callback_server:
            callback_server.stop()


def target_slug(target: str) -> str:
    parsed = urllib.parse.urlsplit(target)
    host = (parsed.hostname or "target").replace(":", "-")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}-{port}"


def write_report(report: dict[str, Any], args: argparse.Namespace, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["output_file"] = str(path)


def output_reports(reports: list[dict[str, Any]], args: argparse.Namespace) -> None:
    if args.output and len(reports) == 1:
        write_report(reports[0], args, args.output)
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for report in reports:
            path = args.output_dir / f"{target_slug(report['target'])}.json"
            write_report(report, args, path)
        if len(reports) > 1:
            summary = args.output_dir / "summary.json"
            summary.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.format == "sarif":
            (args.output_dir / "astroscan.sarif").write_text(
                json.dumps(build_sarif_report(reports), indent=2) + "\n", encoding="utf-8"
            )
    if args.format == "human":
        if not args.quiet:
            for index, report in enumerate(reports):
                if index:
                    print("")
                print(render_human_report(report), end="")
        else:
            for report in reports:
                print(f"AstroScan: {report['target']} -> {report['overall_status']}", file=sys.stderr)
    elif args.format == "json":
        payload: Any = reports[0] if len(reports) == 1 else reports
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.format == "jsonl":
        for report in reports:
            for finding in report["findings"]:
                print(json.dumps({"type": "finding", "target": report["target"], **finding}, sort_keys=True))
            print(json.dumps({
                "type": "summary",
                "target": report["target"],
                "overall_status": report["overall_status"],
                "skipped_modules": report["skipped_modules"],
                "transport_errors": len(report["transport_errors"]),
                "budget_exceeded": report["budget_exceeded"],
            }, sort_keys=True))
    elif args.format == "sarif":
        print(json.dumps(build_sarif_report(reports), indent=2))


def run(args: argparse.Namespace) -> int:
    if args.version:
        print(f"AstroScan {VERSION}")
        return 0
    if args.list_modules:
        print_module_list()
        return 0
    plan = validate_args(args)
    if args.dry_run:
        print(render_plan(plan, args), end="")
        return 0
    reports = []
    exit_code = 0
    for target in plan.targets:
        report = run_target(target, plan, args)
        reports.append(report)
        if args.fail_on_finding and report["overall_status"] == "vulnerable":
            exit_code = max(exit_code, 1)
        if args.fail_on_transport_error and report["transport_errors"]:
            exit_code = max(exit_code, 2)
        if args.fail_on_inconclusive and report["overall_status"] == "inconclusive":
            exit_code = max(exit_code, 2)
    output_reports(reports, args)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except (ValueError, OSError, socket.timeout) as exc:
        print(f"astro_scan: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
