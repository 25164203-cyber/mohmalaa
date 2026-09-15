#!/usr/bin/env python3
"""
SSRFScope isolated training lab.

Starts three local-only services:
  8787  intentionally vulnerable demo application
  8788  simulated internal service with a harmless canary
  8789  OOB callback collector

The demo application intentionally fetches only loopback destinations. This
keeps the exercise useful for SSRF training without turning the lab into an
open proxy. Do not expose it to an untrusted network.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

LAB_CANARY = "LAB_INTERNAL_CANARY_SSRFSCOPE"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def send_json(handler: BaseHTTPRequestHandler, status: int, value: object) -> None:
    payload = json_bytes(value)
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    return handler.rfile.read(max(0, min(length, 64 * 1024)))


def local_only_fetch(target: str, timeout: float = 3.0) -> tuple[int, dict[str, str], bytes]:
    parts = urlsplit(target)
    if parts.scheme not in {"http", "https"} or parts.hostname not in ALLOWED_HOSTS:
        return 403, {}, b"lab policy: only loopback destinations are allowed"
    request = Request(target, headers={"User-Agent": "SSRFScope-Isolated-Lab/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.getcode(), dict(response.headers.items()), response.read(16 * 1024)
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read(16 * 1024)
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return 502, {}, f"upstream error: {type(exc).__name__}: {exc}".encode("utf-8", "replace")


def proxy_result(target: str) -> dict[str, object]:
    status, headers, body = local_only_fetch(target)
    return {
        "requested_target": target,
        "upstream_status": status,
        "upstream_content_type": headers.get("Content-Type", ""),
        "upstream_body_preview": body[:2000].decode("utf-8", "replace"),
        "lab_note": "This endpoint intentionally demonstrates a server-side fetch in a loopback-only lab.",
    }


class DemoAppHandler(BaseHTTPRequestHandler):
    server_version = "SSRFScopeLabApp/1.0"

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        if parts.path == "/":
            send_json(
                self,
                200,
                {
                    "service": "vulnerable-demo-app",
                    "endpoints": [
                        "/fetch?url=...",
                        "/header-fetch with X-Target-URL",
                        "POST /api/fetch with JSON {url: ...}",
                        "POST /form-fetch with url=...",
                    ],
                    "allowed_destination_policy": "loopback only",
                },
            )
            return
        if parts.path == "/fetch":
            target = query.get("url", [""])[0]
            self.handle_proxy(target)
            return
        if parts.path == "/header-fetch":
            target = self.headers.get("X-Target-URL", "")
            self.handle_proxy(target)
            return
        send_json(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        raw = read_body(self)
        target = ""
        if parts.path == "/api/fetch":
            try:
                parsed = json.loads(raw.decode("utf-8"))
                target = str(parsed.get("url", parsed.get("target", "")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                send_json(self, 400, {"error": "body must be a JSON object"})
                return
        elif parts.path == "/form-fetch":
            target = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).get("url", [""])[0]
        else:
            send_json(self, 404, {"error": "not found"})
            return
        self.handle_proxy(target)

    def handle_proxy(self, target: str) -> None:
        if not target:
            send_json(self, 400, {"error": "missing url"})
            return
        result = proxy_result(target)
        send_json(self, 200 if result["upstream_status"] < 400 else 502, result)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[app] {self.address_string()} - {format % args}")


class InternalServiceHandler(BaseHTTPRequestHandler):
    server_version = "SSRFScopeLabInternal/1.0"

    def do_GET(self) -> None:
        send_json(
            self,
            200,
            {
                "service": "internal-demo-service",
                "status": "ok",
                "canary": LAB_CANARY,
                "note": "Harmless training data only; no credentials are present.",
            },
        )

    def log_message(self, format: str, *args: object) -> None:
        print(f"[internal] {self.address_string()} - {format % args}")


class OOBHandler(BaseHTTPRequestHandler):
    server_version = "SSRFScopeLabOOB/1.0"
    events: list[dict[str, object]] = []
    events_lock = threading.Lock()

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == "/events":
            with self.events_lock:
                events = list(self.events)
            send_json(self, 200, {"count": len(events), "events": events})
            return
        event = {
            "time": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "client": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
        }
        with self.events_lock:
            self.events.append(event)
        send_json(self, 204, {"received": True})

    def log_message(self, format: str, *args: object) -> None:
        print(f"[oob] {self.address_string()} - {format % args}")


def serve(handler: type[BaseHTTPRequestHandler], bind: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((bind, port), handler)
    thread = threading.Thread(target=server.serve_forever, name=f"lab-{port}", daemon=True)
    thread.start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SSRFScope isolated SSRF training lab")
    parser.add_argument("--bind", default="127.0.0.1", help="bind address; keep the default for isolation")
    parser.add_argument("--app-port", type=int, default=8787)
    parser.add_argument("--internal-port", type=int, default=8788)
    parser.add_argument("--oob-port", type=int, default=8789)
    args = parser.parse_args()
    if args.bind != "127.0.0.1":
        print("WARNING: the lab is being exposed beyond loopback; use only on an isolated network.")
    servers = [
        serve(DemoAppHandler, args.bind, args.app_port),
        serve(InternalServiceHandler, args.bind, args.internal_port),
        serve(OOBHandler, args.bind, args.oob_port),
    ]
    print(f"Demo app:      http://{args.bind}:{args.app_port}/")
    print(f"Internal demo: http://{args.bind}:{args.internal_port}/")
    print(f"OOB events:    http://{args.bind}:{args.oob_port}/events")
    print("Press Ctrl+C to stop. This lab contains no real credentials.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping lab...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
