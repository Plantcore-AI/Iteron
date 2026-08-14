# Credential-free provider diagnosis

Use this sequence before creating, rotating, or pasting any API key. It proves
local installation and configuration facts without reading credential values.

## 1. Verify the executable and version

```sh
command -v iteron
iteron --version
```

The first command must print the intended installation path and the second must
exit successfully. If resolution fails, add the install directory (normally
`$HOME/.local/bin`) to `PATH`, start a new shell, and repeat. If an older binary
resolves first, fix `PATH` ordering or invoke the intended absolute path.

## 2. Inspect only non-secret configuration

Run `iteron --help` and compare the provider name, model id, endpoint, and CLI
flags with [provider configuration](../reference/providers.md). Check whether the
expected credential *variable name* is configured, but never print its value.
Repository configuration cannot grant provider authority; trusted user config,
CLI input, and the process environment own routing.

## 3. Separate catalog state from authentication

Start Iteron without a key and inspect `/status` and `/model`. An unavailable or
unknown route is a valid diagnostic state. A model appearing in a built-in
catalog does not prove account entitlement, endpoint reachability, or a valid
credential. Do not use a real request as the first installation test.

## 4. Check endpoint reachability without authorization

If policy permits network diagnostics, resolve the configured hostname and make
a bounded HTTPS request that sends no authorization header. A `401` or `403`
still proves DNS, TLS, and HTTP reachability; it does not prove account access.
Do not place tokens in command history, URLs, issue reports, or repository files.

## 5. Load a credential only after local checks pass

Use `iteron setup --byok PROVIDER` or the documented environment variable. Then
restart Iteron so the child process receives the updated environment. Re-check
`/status`; retry a specific model only when intended. Redact headers, account
identifiers, request bodies, and session records from bug reports.

These checks diagnose installation, `PATH`, configuration ownership, catalog
state, and network reachability. They deliberately make no claim about provider
uptime, account entitlement, billing, or model availability.
