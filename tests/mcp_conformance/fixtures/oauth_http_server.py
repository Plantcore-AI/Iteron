#!/usr/bin/env python3
"""Loopback MCP + OAuth fixture with DCR, issuer binding, refresh, and revoke."""

import argparse
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mode",
    choices=(
        "success",
        "no-auth",
        "issuer-mismatch",
        "resource-mismatch",
        "scope-escalation",
        "scope-missing",
        "unsupported-token-auth",
    ),
    default="success",
)
parser.add_argument(
    "--protocol-version",
    choices=("2025-06-18", "2025-11-25", "2026-07-28"),
    default="2025-11-25",
)
ARGUMENTS = parser.parse_args()
MODE = ARGUMENTS.mode


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def log_message(self, _format, *_args):
        return

    def send_json(self, status, value, headers=None):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/.well-known/oauth-protected-resource/mcp":
            if MODE == "no-auth":
                self.send_json(404, {"error": "not_found"})
                return
            self.send_json(
                200,
                {
                    "resource": (
                        f"{self.origin}/other"
                        if MODE == "resource-mismatch"
                        else f"{self.origin}/mcp"
                    ),
                    "authorization_servers": [self.origin],
                },
            )
        elif url.path == "/.well-known/oauth-authorization-server":
            self.send_json(
                200,
                {
                    "issuer": (
                        f"{self.origin}/unexpected"
                        if MODE == "issuer-mismatch"
                        else self.origin
                    ),
                    "authorization_endpoint": f"{self.origin}/authorize",
                    "token_endpoint": f"{self.origin}/token",
                    "registration_endpoint": f"{self.origin}/register",
                    "revocation_endpoint": f"{self.origin}/revoke",
                    "client_id_metadata_document_supported": True,
                    "authorization_response_iss_parameter_supported": True,
                    "token_endpoint_auth_methods_supported": (
                        ["client_secret_basic"]
                        if MODE == "unsupported-token-auth"
                        else ["none"]
                    ),
                },
            )
        elif url.path == "/authorize":
            query = urllib.parse.parse_qs(url.query)
            redirect = query["redirect_uri"][0]
            separator = "&" if "?" in redirect else "?"
            location = (
                f"{redirect}{separator}code=local-code"
                f"&state={urllib.parse.quote(query['state'][0])}"
                f"&iss={urllib.parse.quote(self.origin, safe='')}"
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length", "0")), 1024 * 1024)
        body = self.rfile.read(length)
        if self.path == "/register":
            self.send_json(201, {"client_id": "local-client"})
            return
        if self.path == "/token":
            values = urllib.parse.parse_qs(body.decode())
            if values.get("code") != ["local-code"]:
                self.send_json(400, {"error": "invalid_grant"})
                return
            self.send_json(
                200,
                {
                    "access_token": "local-access",
                    "refresh_token": "local-refresh",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    **(
                        {}
                        if MODE == "scope-missing"
                        else {
                            "scope": "mcp admin" if MODE == "scope-escalation" else "mcp"
                        }
                    ),
                },
            )
            return
        if self.path == "/revoke":
            self.send_json(200, {})
            return
        if self.path == "/mcp":
            if MODE != "no-auth" and self.headers.get("Authorization") != "Bearer local-access":
                self.send_json(401, {"error": "unauthorized"})
                return
            request = json.loads(body)
            method = request.get("method")
            if method == "server/discover":
                if ARGUMENTS.protocol_version != "2026-07-28":
                    self.send_json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "error": {"code": -32601, "message": "Method not found"},
                        },
                    )
                    return
                result = {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                }
            elif method == "initialize":
                result = {
                    "protocolVersion": ARGUMENTS.protocol_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "oauth-fixture", "version": "1"},
                }
            elif method == "tools/list":
                result = {"tools": []}
            else:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_json(
                200,
                {"jsonrpc": "2.0", "id": request.get("id"), "result": result},
            )
            return
        self.send_json(404, {"error": "not_found"})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(f"http://127.0.0.1:{server.server_port}/mcp", flush=True)
server.serve_forever()
