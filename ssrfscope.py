#!/usr/bin/env python3
"""
SSRFScope - a standard-library-only SSRF detection engine.

This tool is intended for authorized security testing and isolated labs.
It performs low-impact HTTP GET/POST probes and reports indicators; it does
not attempt to exfiltrate credentials, execute commands, or bypass access
controls.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)
from urllib.request import (
    HTTPSHandler,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

TOOL_VERSION = "0.2.0"
BASELINE_MARKER = "ssrfscope-baseline"
LOGGER = logging.getLogger("ssrfscope")

# Deliberately conservative defaults. Additional targets must be supplied
# explicitly with --payload; no cloud metadata URL is probed by default.
DEFAULT_PAYLOADS = (
    "http://127.0.0.1:80/",
    "http://localhost:80/",
)
SENSITIVE_PAYLOADS = (
    "http://169.254.169.254/",
)

CONTENT_SIGNATURES: Sequence[Tuple[str, str]] = (
    (r"connection\s+refused", "connection-refused"),
    (r"econnrefused", "econnrefused"),
    (r"no\s+route\s+to\s+host", "no-route-to-host"),
    (r"network\s+is\s+unreachable", "network-unreachable"),
    (r"connection\s+timed\s+out", "connection-timeout"),
    (r"timed\s+out", "timeout"),
    (r"redis[_ -]?version|redis\s+server", "redis"),
    (r"elasticsearch|\"cluster_name\"|_cat/indices", "elasticsearch"),
    (r"mongodb|mongod", "mongodb"),
    (r"postgres(?:ql)?|mysql", "database-banner"),
    (r"kubernetes|kube-apiserver", "kubernetes"),
    (r"instance-id|ami-id|metadata[-_ ]server", "cloud-metadata"),
    (r"169\.254\.169\.254", "metadata-address"),
    (r"lab_internal_canary|internal-demo-service", "lab-internal-canary"),
)


class NoRedirectHandler(HTTPRedirectHandler):
    """Do not follow redirects unless the operator explicitly asks for it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class Target:
    kind: str
    name: str


@dataclass
class ResponseSnapshot:
    status: Optional[int]
    headers: Dict[str, str]
    body: str
    body_length: int
    body_sha256: str
    elapsed_ms: float
    content_type: str
    title: Optional[str]
    signatures: List[str]
    error: Optional[str] = None
    truncated: bool = False

    def public(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "headers": self.headers,
            "body_length": self.body_length,
            "body_sha256": self.body_sha256,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "content_type": self.content_type,
            "title": self.title,
            "signatures": self.signatures,
            "error": self.error,
            "truncated": self.truncated,
            # A bounded body preview makes report review useful without
            # storing a full response by default.
            "body_preview": self.body[:500],
        }


class HTTPClient:
    def __init__(
        self,
        timeout: float,
        max_body_bytes: int,
        follow_redirects: bool,
        insecure: bool,
        user_agent: str,
        delay: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.user_agent = user_agent
        self.delay = max(0.0, delay)
        handlers: List[Any] = []
        if not follow_redirects:
            handlers.append(NoRedirectHandler())
        if insecure:
            handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = build_opener(*handlers)

    def fetch(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[bytes],
    ) -> ResponseSnapshot:
        if self.delay:
            time.sleep(self.delay)
        LOGGER.debug("HTTP %s %s", method.upper(), url)
        request_headers = dict(headers)
        request_headers.setdefault("User-Agent", self.user_agent)
        request_headers.setdefault("Accept", "*/*")
        req = Request(url, data=body, headers=request_headers, method=method.upper())
        started = time.perf_counter()
        response_obj: Any = None
        error: Optional[str] = None
        status: Optional[int] = None
        response_headers: Dict[str, str] = {}
        raw = b""
        truncated = False

        try:
            response_obj = self.opener.open(req, timeout=self.timeout)
            status = getattr(response_obj, "status", None) or response_obj.getcode()
            response_headers = {str(k): str(v) for k, v in response_obj.headers.items()}
            raw = response_obj.read(self.max_body_bytes + 1)
        except HTTPError as exc:
            # HTTP errors still contain valuable response evidence (for
            # example a 500 body returned after an SSRF attempt).
            status = exc.code
            response_headers = {str(k): str(v) for k, v in exc.headers.items()}
            try:
                raw = exc.read(self.max_body_bytes + 1)
            except Exception:
                raw = b""
        except (URLError, HTTPException, TimeoutError, OSError, ValueError) as exc:
            error = _safe_error(exc)
        except Exception as exc:  # defensive boundary for a scanner worker
            error = _safe_error(exc)
        finally:
            if response_obj is not None:
                try:
                    response_obj.close()
                except Exception:
                    pass

        elapsed_ms = (time.perf_counter() - started) * 1000
        if len(raw) > self.max_body_bytes:
            raw = raw[: self.max_body_bytes]
            truncated = True
        body_text = _decode_body(raw, response_headers.get("Content-Type", ""))
        body_hash = hashlib.sha256(raw).hexdigest()
        signatures = detect_signatures(body_text)
        title = extract_title(body_text)
        content_type = response_headers.get("Content-Type", "")
        return ResponseSnapshot(
            status=status,
            headers=response_headers,
            body=body_text,
            body_length=len(raw),
            body_sha256=body_hash,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
            title=title,
            signatures=signatures,
            error=error,
            truncated=truncated,
        )


def _safe_error(exc: BaseException) -> str:
    text = str(exc).replace("\n", " ").strip()
    if len(text) > 240:
        text = text[:237] + "..."
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset\s*=\s*['\"]?([\w.-]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def extract_title(body: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] or None


def detect_signatures(body: str) -> List[str]:
    lowered = body.lower()
    found: List[str] = []
    for pattern, label in CONTENT_SIGNATURES:
        if re.search(pattern, lowered, re.I):
            found.append(label)
    return found


def response_diff_score(baseline: ResponseSnapshot, candidate: ResponseSnapshot) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if baseline.status != candidate.status:
        score += 2
        reasons.append(f"status changed ({baseline.status} -> {candidate.status})")

    if candidate.signatures:
        score += min(3, len(candidate.signatures))
        reasons.append("content signatures: " + ", ".join(candidate.signatures))

    length_delta = abs(candidate.body_length - baseline.body_length)
    # Ignore tiny framework noise; scale the threshold for larger responses.
    length_threshold = max(80, int(max(baseline.body_length, 1) * 0.20))
    if length_delta >= length_threshold:
        score += 1
        reasons.append(f"body length changed by {length_delta} bytes")

    baseline_ms = max(baseline.elapsed_ms, 1.0)
    if candidate.elapsed_ms - baseline.elapsed_ms >= 300 and candidate.elapsed_ms >= baseline_ms * 1.8:
        score += 1
        reasons.append("material response-time increase")

    if baseline.error != candidate.error and candidate.error:
        score += 1
        reasons.append("network/application error differs from baseline")

    if not reasons:
        reasons.append("no material heuristic difference")
    return score, reasons


def parse_header_assignment(value: str) -> Tuple[str, str]:
    name, separator, header_value = value.partition("=")
    name = name.strip()
    if not separator or not name:
        raise ValueError(f"header must use NAME=VALUE: {value!r}")
    return name, header_value


def normalize_headers(assignments: Iterable[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in assignments:
        name, value = parse_header_assignment(item)
        headers[name] = value
    return headers


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise ValueError("URL must be an absolute http:// or https:// URL")


def parse_raw_request(path: str, scheme: str = "http") -> Dict[str, Any]:
    """Parse a Burp-like raw HTTP request using only the standard library."""
    with open(path, "rb") as handle:
        raw = handle.read(4 * 1024 * 1024)
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines:
        raise ValueError("request file is empty")
    try:
        request_line = lines[0].decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid request line encoding") from exc
    pieces = request_line.split()
    if len(pieces) < 2:
        raise ValueError("request file first line must be METHOD PATH [HTTP/VERSION]")
    method, target = pieces[0].upper(), pieces[1]
    headers: Dict[str, str] = {}
    for raw_line in lines[1:]:
        if not raw_line or b":" not in raw_line:
            continue
        key, value = raw_line.split(b":", 1)
        name = key.decode("iso-8859-1").strip()
        headers[name] = value.decode("iso-8859-1").strip()
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        host = headers.get("Host") or headers.get("host")
        if not host:
            raise ValueError("request file needs a Host header for a relative target")
        if not target.startswith("/"):
            target = "/" + target
        url = f"{scheme}://{host}{target}"
    return {"url": url, "method": method, "headers": headers, "body": body}


def json_field_paths(value: Any, prefix: str = "", depth: int = 0) -> List[str]:
    if depth > 5:
        return []
    if isinstance(value, dict):
        paths: List[str] = []
        for key, child in value.items():
            current = f"{prefix}.{key}" if prefix else str(key)
            nested = json_field_paths(child, current, depth + 1)
            paths.extend(nested or [current])
        return paths
    if isinstance(value, list):
        paths = []
        for index, child in enumerate(value[:50]):
            current = f"{prefix}.{index}" if prefix else str(index)
            paths.extend(json_field_paths(child, current, depth + 1) or [current])
        return paths
    return [prefix] if prefix else []


def load_profile(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        profile = json.load(handle)
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    return profile


def apply_request_sources(args: argparse.Namespace) -> None:
    """Merge request-file and profile inputs before target discovery."""
    discovered_headers: Dict[str, str] = {}
    discovered_body = b""
    if args.request_file:
        parsed = parse_raw_request(args.request_file, args.scheme)
        args.url = parsed["url"]
        args.method = args.method or parsed["method"]
        discovered_headers = parsed["headers"]
        discovered_body = parsed["body"]
        content_type = next((v for k, v in discovered_headers.items() if k.lower() == "content-type"), "")
        if discovered_body and "json" in content_type.lower() and not args.body_json:
            args.body_json = discovered_body.decode("utf-8", "replace")
        elif discovered_body and "x-www-form-urlencoded" in content_type.lower() and not args.body_form:
            args.body_form = discovered_body.decode("utf-8", "replace")
    if args.profile:
        profile = load_profile(args.profile)
        profile_headers = profile.get("headers", {})
        if not isinstance(profile_headers, dict):
            raise ValueError("profile.headers must be an object")
        for key, value in profile_headers.items():
            discovered_headers[str(key)] = str(value)
        cookies = profile.get("cookies")
        if isinstance(cookies, dict) and cookies:
            discovered_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if profile.get("user_agent") and not args.user_agent:
            args.user_agent = str(profile["user_agent"])
    explicit_headers = normalize_headers(args.set_header)
    skip = {"host", "content-length", "transfer-encoding"}
    for key, value in discovered_headers.items():
        if key.lower() not in skip and key.lower() not in {h.lower() for h in explicit_headers}:
            args.set_header.append(f"{key}={value}")
    args.discovered_headers = list(discovered_headers)


def replace_query_parameter(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated: List[Tuple[str, str]] = []
    for key, old_value in query:
        if key == name:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))
    if not replaced:
        updated.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment))


def query_parameter_names(url: str) -> List[str]:
    names: List[str] = []
    for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name not in names:
            names.append(name)
    return names


def update_json_body(raw_json: Optional[str], field: str, value: str) -> bytes:
    if raw_json:
        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid --body-json: {exc}") from exc
    else:
        parsed = {}
    if not isinstance(parsed, (dict, list)):
        raise ValueError("--body-json must contain a JSON object or array")
    parts = field.split(".")
    cursor: Any = parsed
    for part in parts[:-1]:
        if isinstance(cursor, dict):
            if part not in cursor or not isinstance(cursor[part], (dict, list)):
                cursor[part] = {}
            cursor = cursor[part]
        elif isinstance(cursor, list) and part.isdigit():
            index = int(part)
            while len(cursor) <= index:
                cursor.append({})
            cursor = cursor[index]
        else:
            raise ValueError(f"cannot traverse JSON field: {field}")
    last = parts[-1]
    if isinstance(cursor, dict):
        cursor[last] = value
    elif isinstance(cursor, list) and last.isdigit():
        index = int(last)
        while len(cursor) <= index:
            cursor.append(None)
        cursor[index] = value
    else:
        raise ValueError(f"cannot set JSON field: {field}")
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def update_form_body(raw_form: Optional[str], field: str, value: str) -> bytes:
    pairs = parse_qsl(raw_form or "", keep_blank_values=True)
    replaced = False
    updated: List[Tuple[str, str]] = []
    for key, old_value in pairs:
        if key == field:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))
    if not replaced:
        updated.append((field, value))
    return urlencode(updated).encode("utf-8")


def make_payloads(args: argparse.Namespace) -> List[Tuple[str, Optional[str]]]:
    payloads = list(args.payload or ())
    if not payloads:
        payloads = list(DEFAULT_PAYLOADS)
        if args.allow_sensitive:
            payloads.extend(SENSITIVE_PAYLOADS)
    result: List[Tuple[str, Optional[str]]] = []
    for item in payloads:
        validate_url(item)
        result.append((item, None))
    if args.oob_template:
        template = args.oob_template
        if "{token}" not in template:
            raise ValueError("--oob-template must contain the {token} placeholder")
        # Validate the template with a token so malformed schemes fail early.
        sample = template.replace("{token}", "sample-token")
        validate_url(sample)
        result.append((template, "template"))
    return result


def build_targets(args: argparse.Namespace) -> List[Target]:
    targets: List[Target] = []

    def add(kind: str, name: str) -> None:
        candidate = Target(kind, name)
        if candidate not in targets:
            targets.append(candidate)

    params = list(args.param or ())
    if args.command == "scan" and not params:
        params = query_parameter_names(args.url)
    for name in params:
        if not name:
            raise ValueError("parameter names cannot be empty")
        add("parameter", name)

    header_names = list(args.header_target or ())
    if args.command == "scan" and args.all_request_headers:
        skipped = {"host", "content-length", "transfer-encoding", "content-type", "user-agent", "accept", "authorization", "cookie"}
        header_names.extend(name for name in getattr(args, "discovered_headers", []) if name.lower() not in skipped)
    for name in header_names:
        if not name.strip():
            raise ValueError("header target names cannot be empty")
        add("header", name.strip())

    if args.body_json_field:
        add("json-body", args.body_json_field)
    elif args.command == "scan" and args.body_json:
        try:
            parsed_json = json.loads(args.body_json)
            for field in json_field_paths(parsed_json):
                add("json-body", field)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid --body-json: {exc}") from exc

    if args.body_form_field:
        add("form-body", args.body_form_field)
    elif args.command == "scan" and args.body_form:
        for field, _ in parse_qsl(args.body_form, keep_blank_values=True):
            add("form-body", field)

    if not targets:
        raise ValueError(
            "no injection point selected; use --param, --header-target, "
            "--body-json-field, --body-form-field, or a request file with --all-request-headers"
        )
    return targets


def request_parts(
    args: argparse.Namespace,
    target: Target,
    injection_value: str,
    static_headers: Dict[str, str],
) -> Tuple[str, str, Dict[str, str], Optional[bytes]]:
    url = args.url
    headers = dict(static_headers)
    body: Optional[bytes] = None

    if target.kind == "parameter":
        url = replace_query_parameter(url, target.name, injection_value)
    elif target.kind == "header":
        headers[target.name] = injection_value
    elif target.kind == "json-body":
        body = update_json_body(args.body_json, target.name, injection_value)
        headers.setdefault("Content-Type", "application/json")
    elif target.kind == "form-body":
        body = update_form_body(args.body_form, target.name, injection_value)
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        raise ValueError(f"unsupported target kind: {target.kind}")

    method = (args.method or ("POST" if body is not None else "GET")).upper()
    return url, method, headers, body


def materialize_payload(template: str, token_kind: Optional[str]) -> Tuple[str, Optional[str]]:
    if token_kind != "template":
        return template, None
    token = uuid.uuid4().hex
    return template.replace("{token}", token), token


def run_probe(
    args: argparse.Namespace,
    client: HTTPClient,
    target: Target,
    payload_templates: Sequence[Tuple[str, Optional[str]]],
    static_headers: Dict[str, str],
    executor: concurrent.futures.Executor,
) -> Dict[str, Any]:
    baseline_url, baseline_method, baseline_headers, baseline_body = request_parts(
        args, target, BASELINE_MARKER, static_headers
    )
    baseline = client.fetch(baseline_url, baseline_method, baseline_headers, baseline_body)

    def one(template_pair: Tuple[str, Optional[str]]) -> Dict[str, Any]:
        template, token_kind = template_pair
        payload, token = materialize_payload(template, token_kind)
        url, method, headers, body = request_parts(args, target, payload, static_headers)
        snapshot = client.fetch(url, method, headers, body)
        score, reasons = response_diff_score(baseline, snapshot)
        severity = "possible-ssrf" if score >= 3 else ("interesting" if score >= 2 else "inconclusive")
        return {
            "target": {"kind": target.kind, "name": target.name},
            "payload": payload,
            "payload_template": template,
            "oob_token": token,
            "request": {"url": url, "method": method},
            "response": snapshot.public(),
            "baseline": baseline.public(),
            "score": score,
            "severity": severity,
            "reasons": reasons,
        }

    futures = [executor.submit(one, item) for item in payload_templates]
    results: List[Dict[str, Any]] = []
    for future in futures:
        results.append(future.result())
    return {
        "target": {"kind": target.kind, "name": target.name},
        "baseline": baseline.public(),
        "attempts": results,
    }


def summarize(groups: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"targets": len(groups), "attempts": 0, "possible_ssrf": 0, "interesting": 0, "inconclusive": 0}
    for group in groups:
        for attempt in group.get("attempts", []):
            counts["attempts"] += 1
            severity = attempt.get("severity")
            key = "possible_ssrf" if severity == "possible-ssrf" else severity
            if key in counts:
                counts[key] += 1
    return counts


def derive_report_path(save_path: str) -> str:
    root, _ = os.path.splitext(save_path)
    return (root or save_path) + ".html"


def _finding_key(attempt: Dict[str, Any]) -> str:
    target = attempt.get("target", {})
    # payload_template remains stable when an OOB token changes between runs.
    payload = attempt.get("payload_template", attempt.get("payload", ""))
    return f"{target.get('kind', '')}|{target.get('name', '')}|{payload}"


def _finding_attempts(document: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    findings: Dict[str, Dict[str, Any]] = {}
    for group in document.get("results", []):
        for attempt in group.get("attempts", []):
            if attempt.get("severity") in {"possible-ssrf", "interesting"}:
                findings[_finding_key(attempt)] = attempt
    return findings


def _severity_rank(value: str) -> int:
    return {"inconclusive": 0, "interesting": 1, "possible-ssrf": 2}.get(value, 0)


def compare_documents(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Return differential findings, not a claim of complete vulnerability coverage."""
    now = _finding_attempts(current)
    old = _finding_attempts(previous)
    new_findings = [attempt for key, attempt in now.items() if key not in old]
    resolved = [attempt for key, attempt in old.items() if key not in now]
    changed: List[Dict[str, Any]] = []
    for key in sorted(set(now) & set(old)):
        current_attempt = now[key]
        previous_attempt = old[key]
        current_signatures = set(current_attempt.get("response", {}).get("signatures", []))
        previous_signatures = set(previous_attempt.get("response", {}).get("signatures", []))
        if (
            current_attempt.get("score", 0) > previous_attempt.get("score", 0)
            or _severity_rank(current_attempt.get("severity", "")) > _severity_rank(previous_attempt.get("severity", ""))
            or current_signatures - previous_signatures
        ):
            changed.append({"current": current_attempt, "previous": previous_attempt})
    return {
        "baseline_generated_at": previous.get("generated_at"),
        "new_count": len(new_findings),
        "resolved_count": len(resolved),
        "changed_count": len(changed),
        "new": new_findings,
        "resolved": resolved,
        "changed": changed,
        "note": "This is a differential comparison between two scans; it is not complete vulnerability or CVE coverage.",
    }


def build_html_report(document: Dict[str, Any]) -> str:
    esc = html.escape
    summary = document.get("summary", {})
    comparison = document.get("comparison", {})
    rows: List[str] = []
    for group in document.get("results", []):
        for attempt in group.get("attempts", []):
            target = attempt.get("target", {})
            response = attempt.get("response", {})
            reasons = "; ".join(attempt.get("reasons", []))
            severity = attempt.get("severity", "inconclusive")
            rows.append(
                "<tr>"
                f"<td><span class='badge {esc(severity)}'>{esc(severity)}</span></td>"
                f"<td>{esc(str(target.get('kind', '')))}: {esc(str(target.get('name', '')))}</td>"
                f"<td><code>{esc(str(attempt.get('payload_template', attempt.get('payload', ''))))}</code></td>"
                f"<td>{esc(str(response.get('status') or 'ERR'))}</td>"
                f"<td>{esc(str(attempt.get('score', 0)))}</td>"
                f"<td>{esc(reasons)}</td>"
                "</tr>"
            )
    if not rows:
        rows.append("<tr><td colspan='6'>لا توجد محاولات مسجلة.</td></tr>")

    new_rows: List[str] = []
    for attempt in comparison.get("new", []):
        target = attempt.get("target", {})
        new_rows.append(
            f"<li><b>{esc(str(target.get('kind', '')))}: {esc(str(target.get('name', '')))}</b> — "
            f"{esc(str(attempt.get('severity', '')))} — {esc(str(attempt.get('payload_template', attempt.get('payload', ''))))}</li>"
        )
    new_section = "".join(new_rows) or "<li>لا توجد اكتشافات جديدة مقارنة بالنتيجة السابقة.</li>"
    comparison_section = ""
    if comparison:
        comparison_section = (
            "<section><h2>الاكتشافات الجديدة مقارنة بالفحص السابق</h2>"
            f"<p>جديدة: <b>{comparison.get('new_count', 0)}</b> | "
            f"تم حلها: <b>{comparison.get('resolved_count', 0)}</b> | "
            f"تغيّرت: <b>{comparison.get('changed_count', 0)}</b></p>"
            f"<ul>{new_section}</ul>"
            "<p class='muted'>هذه مقارنة بين فحصين؛ لا تعني اكتشاف جميع أنواع الثغرات أو جميع CVEs.</p></section>"
        )

    logo_html = ""
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
    try:
        with open(logo_path, "rb") as logo_handle:
            encoded_logo = base64.b64encode(logo_handle.read()).decode("ascii")
        logo_html = f"<img src='data:image/png;base64,{encoded_logo}' alt='شعار SSRFScope' style='width:110px;height:110px;object-fit:cover;border-radius:18px;float:left;margin:0 0 12px 12px'>"
    except OSError:
        pass

    return f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<title>تقرير SSRFScope</title>
<style>
body{{font-family:Tahoma,Arial,sans-serif;background:#f4f7fb;color:#172033;margin:0;padding:24px;line-height:1.7}}
main{{max-width:1240px;margin:auto}}header,section{{background:#fff;border:1px solid #dce3ee;border-radius:14px;padding:20px;margin-bottom:18px;box-shadow:0 3px 12px #17203312}}
h1{{margin-top:0;color:#123b68}}h2{{color:#174f82;border-bottom:1px solid #e5eaf2;padding-bottom:8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}.metric{{background:#eef4fb;border-radius:10px;padding:14px}}.metric b{{display:block;font-size:1.65rem;color:#174f82}}
table{{width:100%;border-collapse:collapse;font-size:.92rem}}th,td{{border-bottom:1px solid #e5eaf2;padding:10px;text-align:right;vertical-align:top}}th{{background:#edf3f9;color:#174f82}}code{{word-break:break-all;background:#f1f3f6;padding:2px 5px;border-radius:4px}}
.badge{{padding:3px 8px;border-radius:999px;font-weight:bold;white-space:nowrap}}.possible-ssrf{{background:#ffd9d9;color:#9b1c1c}}.interesting{{background:#fff0c2;color:#7a5200}}.inconclusive{{background:#e7edf5;color:#526274}}.muted{{color:#68788d;font-size:.9rem}}
@media(max-width:800px){{body{{padding:10px}}table{{font-size:.8rem}}th,td{{padding:6px}}}}
</style>
</head>
<body><main>
<header>{logo_html}<h1>تقرير SSRFScope</h1>
<p><b>الرابط:</b> <code>{esc(str(document.get('url', '')))}</code></p>
<p><b>وقت التقرير:</b> {esc(str(document.get('generated_at', '')))} | <b>الإصدار:</b> {esc(str(document.get('version', '')))}</p>
<div class="grid">
<div class="metric"><b>{summary.get('targets', 0)}</b>نقاط فحص</div>
<div class="metric"><b>{summary.get('attempts', 0)}</b>محاولات</div>
<div class="metric"><b>{summary.get('possible_ssrf', 0)}</b>Possible SSRF</div>
<div class="metric"><b>{summary.get('interesting', 0)}</b>Interesting</div>
<div class="metric"><b>{summary.get('inconclusive', 0)}</b>Inconclusive</div>
</div></header>
{comparison_section}
<section><h2>تفاصيل المحاولات</h2>
<table><thead><tr><th>التصنيف</th><th>نقطة الحقن</th><th>Payload</th><th>Status</th><th>Score</th><th>الأسباب</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></section>
<section><h2>المنهجية والقيود</h2><p>هذا التقرير مبني على مقارنة Baseline وتوقيعات heuristic، ولا يُعد إثباتاً نهائياً للثغرة. يجب التحقق يدوياً داخل النطاق المصرّح به. لا تعني خانة الاكتشافات الجديدة اكتشاف جميع أنواع الثغرات أو جميع CVEs.</p></section>
</main></body></html>"""


def write_html_report(document: Dict[str, Any], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(build_html_report(document))


def print_human_report(document: Dict[str, Any]) -> None:
    summary = document["summary"]
    print(f"Starting SSRFScope {TOOL_VERSION} ({document['command']})")
    print(f"Target: {document['url']}")
    print("Mode: authorized SSRF detection (not a generic port scan)")
    print("Status: completed")
    print(
        "Findings: {possible_ssrf} possible SSRF | {interesting} interesting | "
        "{inconclusive} inconclusive | {attempts} attempts".format(**summary)
    )
    print("-" * 100)
    print("SSRFSCOPE RESULTS")
    print(f"{'SEVERITY':<16} {'INJECTION POINT':<24} {'STATUS':<8} {'SCORE':<6} PAYLOAD")
    print("-" * 100)
    for group in document["results"]:
        for attempt in group["attempts"]:
            target = f"{attempt['target']['kind']}:{attempt['target']['name']}"
            payload = attempt["payload"]
            if len(payload) > 48:
                payload = payload[:45] + "..."
            status = attempt["response"].get("status") or "ERR"
            print(f"{attempt['severity']:<16} {target[:24]:<24} {str(status):<8} {attempt['score']:<6} {payload}")
            if attempt["severity"] != "inconclusive":
                print("  reasons: " + "; ".join(attempt["reasons"]))
    print("-" * 100)
    print("Note: heuristic results require manual verification in the authorized test environment.")


OOB_EVENTS_LOCK = threading.Lock()


def load_oob_events(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_oob_event(path: str, event: Dict[str, Any]) -> None:
    with OOB_EVENTS_LOCK:
        events = load_oob_events(path)
        events.append(event)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(events[-5000:], handle, ensure_ascii=False, indent=2)
            handle.write("\n")


class OOBHandler(BaseHTTPRequestHandler):
    events_file = "ssrfscope-oob-events.json"

    def do_GET(self) -> None:
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": "GET",
            "path": self.path,
            "client": self.client_address[0],
            "headers": {key: value for key, value in self.headers.items()},
        }
        save_oob_event(self.events_file, event)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 65536))
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": "POST",
            "path": self.path,
            "client": self.client_address[0],
            "headers": {key: value for key, value in self.headers.items()},
            "body_preview": body[:500].decode("utf-8", "replace"),
        }
        save_oob_event(self.events_file, event)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info("OOB %s - %s", self.address_string(), format % args)


def run_oob_server(bind: str, port: int, events_file: str) -> int:
    OOBHandler.events_file = events_file
    server = ThreadingHTTPServer((bind, port), OOBHandler)
    print(f"OOB listener: http://{bind}:{port}/<token>")
    print(f"Events file:  {events_file}")
    print("Press Ctrl+C to stop. Use only in an authorized lab.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nStopping OOB listener...")
    finally:
        server.shutdown()
        server.server_close()
    return 0


def dns_encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    output = bytearray()
    for label in name.split("."):
        encoded = label.encode("idna")
        if not encoded or len(encoded) > 63:
            raise ValueError("invalid DNS label")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def dns_question_end(packet: bytes) -> int:
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset + 4
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS question")
        offset += length
    raise ValueError("truncated DNS question")


def dns_rebind_response(query: bytes, address: str, ttl: int) -> bytes:
    if len(query) < 12:
        raise ValueError("short DNS packet")
    end = dns_question_end(query)
    question = query[12:end]
    flags = 0x8180  # response, recursion available, no error
    query_id = struct.unpack("!H", query[:2])[0]
    header = struct.pack("!HHHHHH", query_id, flags, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, max(0, ttl), 4) + socket.inet_aton(address)
    return header + question + answer


def validate_lab_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value}") from exc
    if not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
        raise ValueError("DNS lab accepts only private, loopback, link-local, or reserved IPs")
    if address.version != 4:
        raise ValueError("educational DNS server currently supports IPv4 only")
    return value


def run_dns_rebind_server(bind: str, port: int, first_ip: str, second_ip: str, switch_after: int, ttl: int) -> int:
    validate_lab_ip(first_ip)
    validate_lab_ip(second_ip)
    if switch_after < 1:
        raise ValueError("switch-after must be at least 1")
    counts: Dict[str, int] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    print(f"Educational DNS rebinding server listening on {bind}:{port}")
    print(f"Sequence: {first_ip} for {switch_after} query(s), then {second_ip}; TTL={ttl}")
    print("Use only in the isolated university lab. Press Ctrl+C to stop.")
    try:
        while True:
            packet, client = sock.recvfrom(4096)
            try:
                end = dns_question_end(packet)
                qname_bytes = packet[12:end - 4]
                labels: List[str] = []
                offset = 0
                while offset < len(qname_bytes):
                    length = qname_bytes[offset]
                    offset += 1
                    if length == 0:
                        break
                    labels.append(qname_bytes[offset:offset + length].decode("ascii", "replace"))
                    offset += length
                qname = ".".join(labels).lower()
                counts[qname] = counts.get(qname, 0) + 1
                address = first_ip if counts[qname] <= switch_after else second_ip
                sock.sendto(dns_rebind_response(packet, address, ttl), client)
                LOGGER.info("DNS %s query=%s answer=%s count=%s", client[0], qname, address, counts[qname])
            except (ValueError, OSError, struct.error) as exc:
                LOGGER.warning("ignored malformed DNS packet: %s", exc)
    except KeyboardInterrupt:
        print("\\nStopping DNS rebinding lab server...")
    finally:
        sock.close()
    return 0


def dns_query(host: str, server: str, port: int, timeout: float) -> str:
    query_id = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + dns_encode_name(host) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(4096)
    if len(response) < 12 or struct.unpack("!H", response[:2])[0] != query_id:
        raise ValueError("invalid DNS response")
    offset = dns_question_end(response)
    if len(response) < offset + 16:
        raise ValueError("DNS response has no A answer")
    # The educational server emits a single uncompressed A answer.
    answer_type, answer_class, ttl, data_len = struct.unpack("!HHIH", response[offset + 2:offset + 12])
    if answer_type != 1 or answer_class != 1 or data_len != 4:
        raise ValueError("DNS response is not an A record")
    return socket.inet_ntoa(response[offset + 12:offset + 16])


def show_banner() -> None:
    """Print a terminal-safe fallback of the supplied logo."""
    color = "" if os.environ.get("NO_COLOR") else "\033[38;5;214m"
    dark = "" if os.environ.get("NO_COLOR") else "\033[38;5;236m"
    reset = "" if os.environ.get("NO_COLOR") else "\033[0m"
    print(f"{color}      ⚡                 ⚡{reset}")
    print(f"{dark}        █████  SSRFSCOPE  █████{reset}")
    print(f"{color}      ◉  ◉       ▲       ◉  ◉{reset}")
    print(f"{dark}              ▲  │  ▲{reset}")
    print(f"{dark}           ────┼──┼──┼────{reset}")
    print(f"{color}              │  │  │{reset}")
    print(f"{dark}        SSRF Detection Engine  v{TOOL_VERSION}{reset}")
    print("  Original logo asset: logo.png")
    print("  Use only on authorized targets and isolated labs.\n")


def normalize_target_input(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Target cannot be empty")
    if not re.match(r"^https?://", value, re.I):
        value = "http://" + value
    validate_url(value)
    return value


def prompt_target() -> str:
    while True:
        try:
            value = input("Enter the authorized target URL or IP (include the SSRF path/parameter when known): ")
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)
        try:
            return normalize_target_input(value)
        except ValueError as exc:
            print(f"Error: {exc}")


def prompt_payload() -> Optional[str]:
    try:
        value = input("Payload URL [Enter for defaults; lab example: http://127.0.0.1:8788/]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not value:
        return None
    try:
        validate_url(normalize_target_input(value))
        return normalize_target_input(value)
    except ValueError as exc:
        print(f"Invalid payload: {exc}")
        return None


def prompt_full_scan_source(target: str) -> List[str]:
    """Ask for an injection point when a bare URL has no discoverable parameter."""
    if query_parameter_names(target):
        return []
    print("No query parameter was found in the target URL.")
    print("An SSRF scan needs an injection point, for example:")
    print("  http://host/fetch?url=x  +  parameter: url")
    print("Choose the injection source:")
    print("1) Query parameter")
    print("2) Header")
    print("3) JSON body")
    print("4) Form body")
    print("5) Raw HTTP request file")
    try:
        choice = input("Choose the source: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return []
    if choice == "1":
        while True:
            name = input("Parameter name (example: url): ").strip()
            if name:
                return ["--param", name]
            print("A parameter name is required. Example: url")
    if choice == "2":
        while True:
            name = input("Header name (example: X-Target-URL): ").strip()
            if name:
                return ["--header-target", name]
            print("A header name is required. Example: X-Target-URL")
    if choice == "3":
        body = input('JSON body [example {"url":"x"}]: ').strip() or '{"url":"x"}'
        return ["--body-json", body, "--method", "POST"]
    if choice == "4":
        body = input("Form body [example url=x]: ").strip() or "url=x"
        return ["--body-form", body, "--method", "POST"]
    if choice == "5":
        path = input("Raw request file path: ").strip()
        return ["--request-file", path] if path else []
    print("Invalid source choice.")
    return []


def run_interactive_menu() -> int:
    show_banner()
    target = prompt_target()
    while True:
        print("\n" + "=" * 58)
        print(f"Current target: {target}")
        print("=" * 58)
        print("1) Full scan")
        print("2) Focused probe")
        print("3) Start OOB listener")
        print("4) Generate report from JSON")
        print("5) Start DNS rebinding lab")
        print("6) Change target")
        print("0) Exit")
        try:
            choice = input("Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if choice == "0":
            print("Exiting.")
            return 0
        if choice == "6":
            target = prompt_target()
            continue
        if choice == "1":
            command = ["scan", target]
            command += prompt_full_scan_source(target)
            if command == ["scan", target]:
                print("No injection point selected. Returning to the menu.")
                continue
            payload = prompt_payload()
            if payload:
                command += ["--payload", payload]
            command += ["--save", "interactive-scan.json"]
            main(command)
            continue
        if choice == "2":
            print("\nInjection point type:")
            print("1) Query parameter")
            print("2) Header")
            print("3) JSON body")
            print("4) Form body")
            kind = input("Choose the type: ").strip()
            command = ["probe", target]
            if kind == "1":
                name = input("Parameter name: ").strip()
                command += ["--param", name]
            elif kind == "2":
                name = input("Header name: ").strip()
                command += ["--header-target", name]
            elif kind == "3":
                body = input('JSON body [example {"url":"x"}]: ').strip() or '{"url":"x"}'
                field = input("Field or path: ").strip() or "url"
                command += ["--body-json", body, "--body-json-field", field, "--method", "POST"]
            elif kind == "4":
                body = input("Form body [example url=x]: ").strip() or "url=x"
                field = input("Field name: ").strip() or "url"
                command += ["--body-form", body, "--body-form-field", field, "--method", "POST"]
            else:
                print("Invalid choice.")
                continue
            payload = prompt_payload()
            if payload:
                command += ["--payload", payload]
            command += ["--save", "interactive-probe.json"]
            main(command)
            continue
        if choice == "3":
            port = input("OOB port [8789]: ").strip() or "8789"
            events = input("Events file [ssrfscope-oob-events.json]: ").strip() or "ssrfscope-oob-events.json"
            main(["oob", "start", "--port", port, "--events-file", events])
            continue
        if choice == "4":
            results = input("JSON results path: ").strip()
            if not results:
                print("A JSON path is required.")
                continue
            output = input("HTML path [Enter for automatic name]: ").strip()
            command = ["report", results]
            if output:
                command += ["--output", output]
            main(command)
            continue
        if choice == "5":
            port = input("DNS port [53535]: ").strip() or "53535"
            main(["dns-rebind", "start", "--port", port])
            continue
        print("Invalid choice.")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssrfscope",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="SSRFScope — Nmap-style SSRF reconnaissance and detection for authorized testing.",
        epilog="""
TARGET SPECIFICATION
  TARGET may be a full URL, an IP with an endpoint, or --request-file.
  A bare IP is not enough unless you also provide an injection point.

SCAN TYPES
  scan       discover and test all selected injection points
  probe      test one focused injection point
  oob        run or inspect the callback listener
  report     render an Arabic HTML report
  dns-rebind run the isolated educational DNS lab

OUTPUT
  -oJ FILE   save machine-readable JSON results
  -oH FILE   save the Arabic HTML report
  -v         enable verbose logging

EXAMPLES
  python ssrfscope.py scan http://127.0.0.1:8787/fetch?url=x \\
      --param url --payload http://127.0.0.1:8788/ -oJ scan.json -oH scan.html
  python ssrfscope.py probe https://authorized.example/fetch?url=x --param url
  python ssrfscope.py --help

Use only on systems you own or are explicitly authorized to test.
""",
    )
    parser.add_argument("--version", action="version", version=f"SSRFScope {TOOL_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("scan", "probe"):
        sub = subparsers.add_parser(
            command,
            help="scan selected/all injection points" if command == "scan" else "run focused probes",
        )
        sub.add_argument("url", nargs="?", help="absolute target URL; omit when using --request-file")
        sub.add_argument("--request-file", help="Burp-like raw HTTP request file")
        sub.add_argument("--scheme", default="http", choices=("http", "https"), help="scheme for relative request files")
        sub.add_argument("--profile", help="JSON profile with fixed headers/cookies")
        sub.add_argument("--param", action="append", help="query parameter to inject; repeatable")
        sub.add_argument(
            "--header-target",
            action="append",
            help="request header name to inject; repeatable (use --set-header for fixed headers)",
        )
        sub.add_argument("--all-request-headers", action="store_true", help="also target safe headers discovered in --request-file")
        sub.add_argument("--set-header", action="append", default=[], metavar="NAME=VALUE", help="fixed request header; repeatable")
        sub.add_argument("--payload", action="append", help="explicit http(s) payload; repeatable")
        sub.add_argument("--oob-template", help="callback URL containing {token}; one unique token per attempt")
        sub.add_argument("--allow-sensitive", action="store_true", help="include the guarded link-local metadata address in defaults")
        sub.add_argument("--method", help="HTTP method; defaults to GET or POST when a body is selected")
        sub.add_argument("--body-json", help="JSON body used with --body-json-field; scan auto-discovers scalar fields")
        sub.add_argument("--body-json-field", help="JSON field path to inject, e.g. options.redirect.url")
        sub.add_argument("--body-form", help="form body such as url=original&mode=test")
        sub.add_argument("--body-form-field", help="form field to inject")
        sub.add_argument("--timeout", type=float, default=8.0, help="per-request timeout in seconds")
        sub.add_argument("--workers", type=int, default=4, help="parallel payload workers, 1-32")
        sub.add_argument("--delay", type=float, default=0.0, help="delay before each request, useful for lab rate limits")
        sub.add_argument("--max-body", type=int, default=262144, help="maximum response bytes to parse")
        sub.add_argument("--follow-redirects", action="store_true", help="follow HTTP redirects")
        sub.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
        sub.add_argument("--user-agent", default=f"SSRFScope/{TOOL_VERSION}", help="User-Agent value")
        sub.add_argument("--log-file", help="write debug log to a file")
        sub.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
        sub.add_argument("-oJ", "--save", help="JSON result path; default: ssrfscope-results.json")
        sub.add_argument("-oH", "--report", help="Arabic HTML report path; default: derived from --save")
        sub.add_argument("--no-auto-report", action="store_true", help="disable automatic HTML report generation")
        sub.add_argument("--compare", help="previous JSON result file for differential findings")
        sub.add_argument("--json", action="store_true", help="print JSON instead of human output")
        sub.add_argument("--fail-on-findings", action="store_true", help="exit 2 if a possible SSRF is reported")

    report_parser = subparsers.add_parser("report", help="generate an Arabic HTML report from JSON")
    report_parser.add_argument("results", help="JSON result file generated by scan/probe")
    report_parser.add_argument("-oH", "--output", help="HTML output path; defaults to the JSON filename with .html")
    report_parser.add_argument("--compare", help="previous JSON result for differential findings")

    oob_parser = subparsers.add_parser("oob", help="local OOB callback listener and event store")
    oob_actions = oob_parser.add_subparsers(dest="oob_action", required=True)
    oob_start = oob_actions.add_parser("start", help="start an HTTP callback listener")
    oob_start.add_argument("--bind", default="127.0.0.1")
    oob_start.add_argument("--port", type=int, default=8789)
    oob_start.add_argument("--events-file", default="ssrfscope-oob-events.json")
    oob_events = oob_actions.add_parser("events", help="show captured callbacks")
    oob_events.add_argument("--events-file", default="ssrfscope-oob-events.json")
    oob_events.add_argument("--pretty", action="store_true")
    oob_clear = oob_actions.add_parser("clear", help="clear captured callbacks")
    oob_clear.add_argument("--events-file", default="ssrfscope-oob-events.json")

    dns_parser = subparsers.add_parser("dns-rebind", help="educational loopback-only DNS rebinding lab server")
    dns_actions = dns_parser.add_subparsers(dest="dns_action", required=True)
    dns_start = dns_actions.add_parser("start", help="start the UDP DNS lab server")
    dns_start.add_argument("--bind", default="127.0.0.1")
    dns_start.add_argument("--port", type=int, default=53535)
    dns_start.add_argument("--first-ip", default="198.51.100.10")
    dns_start.add_argument("--second-ip", default="127.0.0.1")
    dns_start.add_argument("--switch-after", type=int, default=1)
    dns_start.add_argument("--ttl", type=int, default=1)
    dns_query_parser = dns_actions.add_parser("query", help="query a running educational DNS server")
    dns_query_parser.add_argument("hostname")
    dns_query_parser.add_argument("--server", default="127.0.0.1")
    dns_query_parser.add_argument("--port", type=int, default=53535)
    dns_query_parser.add_argument("--count", type=int, default=2)
    dns_query_parser.add_argument("--timeout", type=float, default=2.0)
    return parser


def execute(args: argparse.Namespace) -> Dict[str, Any]:
    logging.basicConfig(
        filename=args.log_file or None,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    apply_request_sources(args)
    if not args.url:
        raise ValueError("provide URL or --request-file")
    if args.timeout <= 0 or args.max_body <= 0 or not (1 <= args.workers <= 32):
        raise ValueError("timeout/max-body must be positive and workers must be between 1 and 32")
    validate_url(args.url)
    payload_templates = make_payloads(args)
    targets = build_targets(args)
    static_headers = normalize_headers(args.set_header)
    client = HTTPClient(
        timeout=args.timeout,
        max_body_bytes=args.max_body,
        follow_redirects=args.follow_redirects,
        insecure=args.insecure,
        user_agent=args.user_agent,
        delay=args.delay,
    )

    groups: List[Dict[str, Any]] = []
    # One executor is shared across targets and payloads. Baselines are made
    # before the payload tasks for each target, so comparisons stay meaningful.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for target in targets:
            groups.append(run_probe(args, client, target, payload_templates, static_headers, executor))

    document: Dict[str, Any] = {
        "tool": "SSRFScope",
        "version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": args.command,
        "url": args.url,
        "results": groups,
        "summary": summarize(groups),
        "methodology": {
            "baseline": BASELINE_MARKER,
            "redirects_followed": bool(args.follow_redirects),
            "tls_verification_disabled": bool(args.insecure),
            "heuristics": ["status", "content signatures", "body length", "response time", "errors"],
        },
    }
    if getattr(args, "compare", None):
        with open(args.compare, "r", encoding="utf-8") as handle:
            previous = json.load(handle)
        document["comparison"] = compare_documents(document, previous)
    if getattr(args, "report", None) and not getattr(args, "no_auto_report", False):
        document["report_path"] = args.report
    if args.save:
        with open(args.save, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    return document


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv or (argv and argv[0] in {"menu", "interactive"}):
        return run_interactive_menu()
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "oob":
            if args.oob_action == "start":
                if args.bind != "127.0.0.1":
                    print("WARNING: OOB listener is exposed beyond loopback; use only in an isolated authorized lab.", file=sys.stderr)
                return run_oob_server(args.bind, args.port, args.events_file)
            if args.oob_action == "events":
                output = load_oob_events(args.events_file)
                print(json.dumps(output, ensure_ascii=False, indent=2 if args.pretty else None))
                return 0
            if args.oob_action == "clear":
                with open(args.events_file, "w", encoding="utf-8") as handle:
                    handle.write("[]\n")
                print(f"Cleared OOB events: {args.events_file}")
                return 0

        if args.command == "dns-rebind":
            if args.dns_action == "start":
                if args.bind != "127.0.0.1":
                    print("WARNING: DNS lab server is exposed beyond loopback; use only in an isolated network.", file=sys.stderr)
                return run_dns_rebind_server(
                    args.bind, args.port, args.first_ip, args.second_ip, args.switch_after, args.ttl
                )
            if args.dns_action == "query":
                if args.count < 1:
                    raise ValueError("count must be at least 1")
                answers = [dns_query(args.hostname, args.server, args.port, args.timeout) for _ in range(args.count)]
                print(json.dumps({"hostname": args.hostname, "server": args.server, "answers": answers}, ensure_ascii=False, indent=2))
                return 0

        if args.command == "report":
            with open(args.results, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            if args.compare:
                with open(args.compare, "r", encoding="utf-8") as handle:
                    document["comparison"] = compare_documents(document, json.load(handle))
            output = args.output or derive_report_path(args.results)
            write_html_report(document, output)
            print(f"Report created: {output}")
            if document.get("comparison"):
                comparison = document["comparison"]
                print(
                    f"New findings: {comparison.get('new_count', 0)} | "
                    f"Resolved: {comparison.get('resolved_count', 0)} | "
                    f"Changed: {comparison.get('changed_count', 0)}"
                )
            return 0

        # Scans always produce a machine-readable result and, unless disabled,
        # an HTML report automatically.
        args.save = args.save or "ssrfscope-results.json"
        if not args.no_auto_report:
            args.report = args.report or derive_report_path(args.save)
        document = execute(args)
        if args.report and not args.no_auto_report:
            write_html_report(document, args.report)
            print(
                f"Report generated automatically: {args.report}",
                file=sys.stderr if args.json else sys.stdout,
            )
        if args.json:
            print(json.dumps(document, ensure_ascii=False, indent=2))
        else:
            print_human_report(document)
        if args.fail_on_findings and document["summary"]["possible_ssrf"]:
            return 2
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
