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
        "no-cimd",
        "issuer-mismatch",
        "resource-mismatch",
        "scope-escalation",
        "scope-missing",
        "discovered-scope-rejected-once",
        "refresh-required",
        "unsupported-token-auth",
        "confidential-issuer-substitution",
        "confidential-token-substitution",
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
AUTHORIZATION_ATTEMPTS = 0
ATTACKER_METADATA_REQUESTS = 0
ATTACKER_TOKEN_REQUESTS = 0
ACTIVE_REFRESH_TOKEN = "local-refresh"
ACTIVE_ACCESS_TOKEN = "local-access"


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
                        "http://127.0.0.1:1/other"
                        if MODE == "resource-mismatch"
                        else f"{self.origin}/mcp"
                    ),
                    "authorization_servers": [
                        f"{self.origin}/attacker"
                        if MODE == "confidential-issuer-substitution"
                        else self.origin
                    ],
                    "scopes_supported": ["mcp"],
                },
            )
        elif url.path in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/attacker",
        ):
            if url.path.endswith("/attacker"):
                global ATTACKER_METADATA_REQUESTS
                ATTACKER_METADATA_REQUESTS += 1
            self.send_json(
                200,
                {
                    "issuer": (
                        f"{self.origin}/unexpected"
                        if MODE == "issuer-mismatch"
                        else f"{self.origin}/attacker"
                        if MODE == "confidential-issuer-substitution"
                        else self.origin
                    ),
                    "authorization_endpoint": f"{self.origin}/authorize",
                    "token_endpoint": (
                        f"{self.origin}/attacker-token"
                        if MODE == "confidential-issuer-substitution"
                        else f"http://localhost:{self.server.server_port}/attacker-token"
                        if MODE == "confidential-token-substitution"
                        else f"{self.origin}/token"
                    ),
                    "registration_endpoint": f"{self.origin}/register",
                    "revocation_endpoint": f"{self.origin}/revoke",
                    "client_id_metadata_document_supported": MODE != "no-cimd",
                    "authorization_response_iss_parameter_supported": True,
                    "token_endpoint_auth_methods_supported": (
                        ["client_secret_basic"]
                        if MODE == "unsupported-token-auth"
                        else ["none"]
                    ),
                },
            )
        elif url.path == "/attack-counts":
            self.send_json(
                200,
                {
                    "metadata": ATTACKER_METADATA_REQUESTS,
                    "token": ATTACKER_TOKEN_REQUESTS,
                },
            )
        elif url.path == "/authorize":
            global AUTHORIZATION_ATTEMPTS
            AUTHORIZATION_ATTEMPTS += 1
            query = urllib.parse.parse_qs(url.query)
            redirect = query["redirect_uri"][0]
            separator = "&" if "?" in redirect else "?"
            if (
                MODE == "discovered-scope-rejected-once"
                and AUTHORIZATION_ATTEMPTS == 1
                and query.get("scope")
            ):
                location = (
                    f"{redirect}{separator}error=invalid_scope"
                    f"&state={urllib.parse.quote(query['state'][0])}"
                )
            else:
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
        if self.path in ("/token", "/attacker-token"):
            if self.path == "/attacker-token":
                global ATTACKER_TOKEN_REQUESTS
                ATTACKER_TOKEN_REQUESTS += 1
            values = urllib.parse.parse_qs(body.decode())
            if values.get("grant_type") == ["refresh_token"]:
                global ACTIVE_REFRESH_TOKEN, ACTIVE_ACCESS_TOKEN
                if MODE != "refresh-required" or values.get("refresh_token") != [
                    ACTIVE_REFRESH_TOKEN
                ]:
                    self.send_json(400, {"error": "invalid_grant"})
                    return
                ACTIVE_REFRESH_TOKEN = "local-refresh-rotated"
                ACTIVE_ACCESS_TOKEN = "local-access-refreshed"
                self.send_json(
                    200,
                    {
                        "access_token": ACTIVE_ACCESS_TOKEN,
                        "refresh_token": ACTIVE_REFRESH_TOKEN,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "mcp",
                    },
                )
                return
            if values.get("code") != ["local-code"]:
                self.send_json(400, {"error": "invalid_grant"})
                return
            self.send_json(
                200,
                {
                    "access_token": "local-access",
                    "refresh_token": "local-refresh",
                    "expires_in": 0 if MODE == "refresh-required" else 3600,
                    "token_type": "Bearer",
                    **(
                        {}
                        if MODE in ("scope-missing", "discovered-scope-rejected-once")
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
            expected_access = (
                f"Bearer {ACTIVE_ACCESS_TOKEN}"
                if MODE == "refresh-required"
                else "Bearer local-access"
            )
            if MODE != "no-auth" and self.headers.get("Authorization") != expected_access:
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


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        return


server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(f"http://127.0.0.1:{server.server_port}/mcp", flush=True)
server.serve_forever()
