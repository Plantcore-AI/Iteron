#!/usr/bin/env python3
"""Bounded process adapter for official MCP client conformance scenarios."""

import ipaddress
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

CIMD_CLIENT_ID = "https://conformance-test.local/client-metadata.json"
SECRET_ENV = "ITERON_CONFORMANCE_CLIENT_SECRET"
REJECTION_SCENARIOS = {
    "auth/resource-mismatch",
    "auth/iss-supported-missing",
    "auth/iss-wrong-issuer",
    "auth/iss-unexpected",
    "auth/iss-normalized",
    "auth/metadata-issuer-mismatch",
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def open_no_redirect(url):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(Request(url, method="GET"), timeout=10) as response:
            return response.status, response.headers.get("Location")
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.headers.get("Location")
        finally:
            error.close()


def is_loopback(host):
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def callback_url(authorize_url, location):
    authorization = urllib.parse.urlsplit(authorize_url)
    query = urllib.parse.parse_qs(authorization.query, keep_blank_values=True)
    redirects = query.get("redirect_uri")
    states = query.get("state")
    if not redirects or len(redirects) != 1 or not states or len(states) != 1:
        raise RuntimeError("authorization URL omitted its exact redirect or state")
    expected = urllib.parse.urlsplit(redirects[0])
    callback = urllib.parse.urlsplit(urllib.parse.urljoin(authorize_url, location))
    if (
        expected.scheme != "http"
        or not is_loopback(expected.hostname)
        or expected.port is None
        or (callback.scheme, callback.hostname, callback.port, callback.path)
        != (expected.scheme, expected.hostname, expected.port, expected.path)
    ):
        raise RuntimeError("authorization redirect escaped the loopback callback")
    values = urllib.parse.parse_qs(callback.query, keep_blank_values=True)
    if values.get("state") != states:
        raise RuntimeError("authorization redirect changed OAuth state")
    return urllib.parse.urlunsplit(callback)


def conformance_context():
    value = json.loads(os.environ.get("MCP_CONFORMANCE_CONTEXT", "{}"))
    if not isinstance(value, dict):
        raise RuntimeError("MCP_CONFORMANCE_CONTEXT must be an object")
    return value


def command(binary, environment, *arguments, timeout=30):
    return subprocess.run(
        [binary, *arguments],
        env=environment,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def login(binary, environment, name, *, scopes=None, client_id=None, secret_env=None):
    arguments = [
        binary,
        "mcp",
        "auth",
        "login",
        name,
        "--oauth-client-registration",
        "auto",
    ]
    if scopes:
        arguments.extend(["--scopes", ",".join(scopes)])
    if client_id:
        arguments.extend(["--client-id", client_id])
    if secret_env:
        arguments.extend(["--client-secret-env", secret_env])
    process = subprocess.Popen(
        arguments,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 20
    authorization_url = None
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    pending = bytearray()
    try:
        while time.monotonic() < deadline:
            ready = selector.select(
                timeout=min(0.25, max(0.0, deadline - time.monotonic()))
            )
            if not ready:
                if process.poll() is not None:
                    break
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            pending.extend(chunk)
            if len(pending) > 16 * 1024:
                raise RuntimeError("login authorization output exceeded its bound")
            while b"\n" in pending:
                line, _, pending = pending.partition(b"\n")
                candidate = line.strip().decode("utf-8", errors="strict")
                if candidate.startswith(("http://", "https://")):
                    authorization_url = candidate
                    break
            if authorization_url is not None:
                break
        if authorization_url is None:
            if process.poll() is None:
                raise RuntimeError("login did not emit an authorization URL within its bound")
            if process.returncode == 0:
                return True
            return False
        status, location = open_no_redirect(authorization_url)
        if status not in {301, 302, 303, 307, 308} or not location:
            raise RuntimeError("authorization endpoint did not return a callback redirect")
        callback = callback_url(authorization_url, location)
        callback_status, _ = open_no_redirect(callback)
        if not 200 <= callback_status < 500:
            raise RuntimeError("loopback callback returned an invalid status")
        return process.wait(timeout=20) == 0
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def stored_credential(config_root):
    directory = config_root / ".iteron" / "mcp-credentials"
    files = [path for path in directory.iterdir() if path.suffix != ".pending"]
    if len(files) != 1:
        raise RuntimeError("OAuth login did not create exactly one credential")
    value = json.loads(files[0].read_text(encoding="utf-8"))
    return value


def stored_token(config_root):
    token = stored_credential(config_root).get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("stored credential omitted the access token")
    return token


def authenticated_call(binary, client, server_url, version, environment, config_root):
    production = command(
        binary,
        environment,
        "mcp",
        "auth",
        "status",
        "official",
        "--format",
        "json",
    )
    if production.returncode != 0:
        return False, []
    try:
        diagnostic = json.loads(production.stdout)
    except json.JSONDecodeError:
        return False, []
    if diagnostic.get("authentication") != "authenticated":
        return False, []
    call_environment = environment.copy()
    call_environment["ITERON_MCP_PROTOCOL_VERSION"] = version
    call_environment["MCP_CONFORMANCE_SCENARIO"] = "auth/tool-call"
    call_environment["ITERON_CONFORMANCE_ACCESS_TOKEN"] = stored_token(config_root)
    completed = command(client, call_environment, server_url)
    if completed.returncode == 0:
        return True, []
    marker = "MCP HTTP endpoint requires additional OAuth scope: "
    for line in completed.stderr.splitlines():
        if marker in line:
            scopes = line.split(marker, 1)[1].strip().split(",")
            if scopes and all(scopes):
                return False, scopes
    return False, []


def run_auth(server_url):
    binary = os.environ.get("ITERON_CONFORMANCE_CLI")
    client = os.environ.get("ITERON_CONFORMANCE_CLIENT")
    if not binary or not client:
        raise RuntimeError("auth conformance requires both Iteron executables")
    scenario = os.environ["MCP_CONFORMANCE_SCENARIO"]
    version = os.environ["ITERON_MCP_PROTOCOL_VERSION"]
    values = conformance_context()
    with tempfile.TemporaryDirectory(prefix="iteron-auth-conformance-") as temp:
        config_root = Path(temp)
        environment = os.environ.copy()
        environment["ITERON_CONFIG_HOME"] = str(config_root)
        client_id = None
        secret_env = None
        if scenario == "auth/basic-cimd":
            client_id = CIMD_CLIENT_ID
        elif scenario == "auth/pre-registration":
            client_id = values.get("client_id")
            secret = values.get("client_secret")
            if not isinstance(client_id, str) or not isinstance(secret, str):
                raise RuntimeError("pre-registration context omitted client credentials")
            environment[SECRET_ENV] = secret
            secret_env = SECRET_ENV
        add = ["mcp", "add", "official", "--url", server_url]
        if client_id:
            add.extend(["--oauth-client-id", client_id])
        if secret_env:
            add.extend(["--oauth-client-secret-env", secret_env])
        if command(binary, environment, *add).returncode != 0:
            return False
        accepted = login(
            binary,
            environment,
            "official",
            client_id=client_id,
            secret_env=secret_env,
        )
        if scenario in REJECTION_SCENARIOS:
            return not accepted
        if not accepted:
            return False
        if scenario == "auth/scope-step-up":
            succeeded, challenged = authenticated_call(
                binary, client, server_url, version, environment, config_root
            )
            if succeeded or not challenged:
                return False
            if not login(
                binary,
                environment,
                "official",
                scopes=challenged,
            ):
                return False
        elif scenario == "auth/scope-retry-limit":
            succeeded, challenged = authenticated_call(
                binary, client, server_url, version, environment, config_root
            )
            if succeeded or not challenged:
                return False
            if not login(
                binary,
                environment,
                "official",
                scopes=challenged,
            ):
                return False
            succeeded, _ = authenticated_call(
                binary, client, server_url, version, environment, config_root
            )
            return not succeeded
        elif scenario == "auth/authorization-server-migration":
            succeeded, _ = authenticated_call(
                binary, client, server_url, version, environment, config_root
            )
            if succeeded:
                return False
            if not login(binary, environment, "official"):
                return False
        succeeded, _ = authenticated_call(
            binary, client, server_url, version, environment, config_root
        )
        return succeeded


def run_non_auth(server_url):
    executable = os.environ.get("ITERON_CONFORMANCE_CLIENT")
    if not executable:
        raise RuntimeError("ITERON_CONFORMANCE_CLIENT is required")
    completed = command(executable, os.environ.copy(), server_url, timeout=60)
    return completed.returncode == 0


def main():
    if len(sys.argv) != 2:
        return 2
    try:
        scenario = os.environ.get("MCP_CONFORMANCE_SCENARIO", "")
        success = run_auth(sys.argv[1]) if scenario.startswith("auth/") else run_non_auth(sys.argv[1])
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"adapter failed: {type(error).__name__}: {error}", file=sys.stderr)
        success = False
    report = {
        "success": success,
        "protocolVersion": os.environ.get("ITERON_MCP_PROTOCOL_VERSION"),
    }
    report_path = os.environ.get("ITERON_CONFORMANCE_ADAPTER_REPORT")
    if report_path:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
