"""Pinned Harbor installed-agent adapter for the Core Code CLI.

This module intentionally does not download an unversioned release.  The caller
supplies one host-side Linux binary and its SHA-256; Harbor uploads those exact
bytes into every fresh task environment.  Import it with Harbor's custom-agent
surface, for example ``core_code_agent:CoreCodeAgent``.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import shlex
import stat
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from harbor.agents.installed.base import BaseInstalledAgent, with_prompt_template
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext
from harbor.models.trial.paths import EnvironmentPaths

_MAX_BINARY_BYTES = 256 * 1024 * 1024
_SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")
_REMOTE_BINARY = PurePosixPath("/usr/local/bin/core")
_BUILTIN_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "glm": "GLM_API_KEY",
    "minimax": "MINIMAX_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
}
_ELF_MACHINES = {62: "x86_64", 183: "aarch64"}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_sha256(value: str) -> str:
    match = _SHA256_RE.fullmatch(value)
    if match is None:
        raise ValueError("binary_sha256 must be 64 lowercase hex digits")
    return match.group(1)


def _linux_binary_arch(path: Path) -> str:
    with path.open("rb") as source:
        header = source.read(20)
    if (
        len(header) != 20
        or header[:4] != b"\x7fELF"
        or header[4] != 2
        or header[5] != 1
        or int.from_bytes(header[16:18], "little") not in {2, 3}
    ):
        raise ValueError(
            "Core binary must be a little-endian 64-bit Linux ELF executable"
        )
    try:
        return _ELF_MACHINES[int.from_bytes(header[18:20], "little")]
    except KeyError as error:
        raise ValueError(
            "Core binary architecture must be x86_64 or aarch64"
        ) from error


def _split_model_route(model_name: str, provider: str | None) -> tuple[str, str]:
    model_name = model_name.strip()
    if not model_name or any(character in model_name for character in "\r\n\0"):
        raise ValueError("model_name must be non-empty and single-line")
    if provider is not None:
        provider = provider.strip()
        if not provider or any(character in provider for character in "\r\n\0"):
            raise ValueError("provider must be non-empty and single-line")
        if "/" in model_name:
            routed_provider, routed_model = model_name.split("/", 1)
            if routed_provider != provider or not routed_model:
                raise ValueError("explicit provider conflicts with model_name route")
            return provider, routed_model
        return provider, model_name
    if "/" not in model_name:
        raise ValueError(
            "model_name must be provider/model unless kwargs.provider is explicit"
        )
    inferred_provider, routed_model = model_name.split("/", 1)
    if not inferred_provider or not routed_model:
        raise ValueError("model_name must be provider/model")
    return inferred_provider, routed_model


class CoreCodeAgent(BaseInstalledAgent):
    """Run one exact Core binary inside a Harbor task environment.

    Harbor remains authoritative for the task image, CPU/memory/storage limits,
    task-specific agent timeout, verifier timeout, artifacts, and repetitions.
    Core receives the instruction and works in ``/app``.  Its user config,
    memory, hooks, MCP declarations, sessions, and caches start under fresh
    private roots; a task-provided ``/app/.core`` path is refused rather than
    allowed to perturb an evaluation arm.
    """

    SUPPORTS_ATIF = False
    SUPPORTS_RESUME = False
    _OUTPUT_FILENAME = "core.stream.jsonl"

    def __init__(
        self,
        logs_dir: Path,
        *,
        binary_path: str | Path,
        binary_sha256: str,
        binary_arch: str,
        provider: str | None = None,
        base_url: str | None = None,
        key_env: str | None = None,
        max_turns: int = 250,
        max_wall_secs: int = 12_000,
        effort: str | None = None,
        autonomous: bool = True,
        extra_env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        supplied_env = dict(extra_env) if extra_env else {}
        super().__init__(logs_dir, extra_env=supplied_env, **kwargs)

        path = Path(binary_path)
        if not path.is_absolute():
            raise ValueError("binary_path must be absolute")
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError(f"cannot inspect Core binary: {error}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("binary_path must be a regular non-symlink file")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_BINARY_BYTES:
            raise ValueError(f"Core binary must contain 1..={_MAX_BINARY_BYTES} bytes")
        self._binary_path = path.resolve(strict=True)
        self._binary_sha256 = _normalize_sha256(binary_sha256)
        if _file_sha256(self._binary_path) != self._binary_sha256:
            raise ValueError("Core binary SHA-256 does not match binary_sha256")
        actual_arch = _linux_binary_arch(self._binary_path)
        if binary_arch not in set(_ELF_MACHINES.values()):
            raise ValueError("binary_arch must be x86_64 or aarch64")
        if actual_arch != binary_arch:
            raise ValueError("Core ELF architecture does not match binary_arch")

        if not 1 <= max_turns <= 100_000:
            raise ValueError("max_turns must be in 1..=100000")
        if not 1 <= max_wall_secs <= 86_400:
            raise ValueError("max_wall_secs must be in 1..=86400")
        if effort not in {None, "low", "medium", "high", "xhigh", "max", "ultracode"}:
            raise ValueError("effort is not a supported Core effort level")
        if (base_url is None) != (key_env is None):
            raise ValueError("base_url and key_env must be supplied together")
        if key_env is not None and _ENV_NAME_RE.fullmatch(key_env) is None:
            raise ValueError("key_env must be an uppercase ASCII environment name")
        if base_url is not None:
            parsed = urlsplit(base_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("base_url must be a credential-free HTTPS URL")

        if not self.model_name:
            raise ValueError("model_name is required")
        resolved_provider, _ = _split_model_route(self.model_name, provider)
        credential_env = key_env or _BUILTIN_KEY_ENVS.get(resolved_provider)
        if credential_env is None:
            raise ValueError("provider has no pinned builtin credential environment")
        if set(supplied_env) != {credential_env} or not supplied_env.get(
            credential_env
        ):
            raise ValueError(
                "agent env must contain exactly the selected credential environment"
            )

        self._provider = provider
        self._base_url = base_url
        self._key_env = key_env
        self._max_turns = max_turns
        self._max_wall_secs = max_wall_secs
        self._effort = effort
        self._autonomous = autonomous
        self._credential_env = credential_env
        nonce = secrets.token_hex(16)
        self._remote_upload = PurePosixPath(f"/tmp/core-code-upload-{nonce}")
        self._remote_home = PurePosixPath(f"/tmp/core-harbor-home-{nonce}")
        self._remote_config_home = PurePosixPath(f"/tmp/core-harbor-config-{nonce}")

    @staticmethod
    def name() -> str:
        return "core-code"

    def get_version_command(self) -> str | None:
        return f"{_REMOTE_BINARY} --version"

    def parse_version(self, stdout: str) -> str:
        return stdout.strip()

    async def install(self, environment: BaseEnvironment) -> None:
        await environment.upload_file(self._binary_path, self._remote_upload.as_posix())
        expected = shlex.quote(self._binary_sha256)
        uploaded = shlex.quote(self._remote_upload.as_posix())
        destination = shlex.quote(_REMOTE_BINARY.as_posix())
        contract = shlex.quote(
            (EnvironmentPaths.agent_dir / "core-machine-contract.json").as_posix()
        )
        credential_env = shlex.quote(self._credential_env)
        await self.exec_as_root(
            environment,
            command=(
                f"set -eu; unset {credential_env}; umask 077; "
                f"trap 'rm -f {uploaded}' EXIT; "
                f"test -f {uploaded}; test ! -L {uploaded}; "
                f"test ! -e {destination}; test ! -L {destination}; "
                f"test ! -e {contract}; test ! -L {contract}; "
                f"actual=$(sha256sum {uploaded} | awk '{{print $1}}'); "
                f'test "$actual" = {expected}; '
                f"install -m 0755 {uploaded} {destination}; "
                f"installed=$(sha256sum {destination} | awk '{{print $1}}'); "
                f'test "$installed" = {expected}; '
                f"{destination} --machine-contract > {contract}"
            ),
        )

    @with_prompt_template
    async def run(
        self, instruction: str, environment: BaseEnvironment, context: AgentContext
    ) -> None:
        del context
        assert self.model_name is not None
        provider, model = _split_model_route(self.model_name, self._provider)

        arguments = [
            _REMOTE_BINARY.as_posix(),
            "--print",
            "--repo",
            "/app",
            "--output-format",
            "stream-json",
            "--model",
            model,
            "--max-turns",
            str(self._max_turns),
            "--max-wall-secs",
            str(self._max_wall_secs),
            "--allow-code",
            "--runs-dir",
            (EnvironmentPaths.agent_dir / "runs").as_posix(),
        ]
        if self._base_url is not None:
            arguments.extend(
                ["--base-url", self._base_url, "--key-env", self._key_env or ""]
            )
        else:
            arguments.extend(["--provider", provider])
        if self._effort is not None:
            arguments.extend(["--effort", self._effort])
        if self._autonomous:
            arguments.append("--dangerously-bypass-permissions")
        arguments.extend(["--", instruction])

        output = shlex.quote(
            (EnvironmentPaths.agent_dir / self._OUTPUT_FILENAME).as_posix()
        )
        env = {
            "HOME": self._remote_home.as_posix(),
            "CORE_CONFIG_HOME": self._remote_config_home.as_posix(),
        }
        runs = EnvironmentPaths.agent_dir / "runs"
        command = (
            "set -eu; umask 077; "
            f"test ! -e {shlex.quote(self._remote_home.as_posix())}; "
            f"test ! -L {shlex.quote(self._remote_home.as_posix())}; "
            f"test ! -e {shlex.quote(self._remote_config_home.as_posix())}; "
            f"test ! -L {shlex.quote(self._remote_config_home.as_posix())}; "
            f"test ! -e {shlex.quote(runs.as_posix())}; test ! -L {shlex.quote(runs.as_posix())}; "
            f"test ! -e {output}; test ! -L {output}; "
            f"install -d -m 0700 {shlex.quote(self._remote_home.as_posix())} "
            f"{shlex.quote(self._remote_config_home.as_posix())} "
            f"{shlex.quote(runs.as_posix())}; "
            "if [ -e /app/.core ] || [ -L /app/.core ]; then "
            "echo 'refusing task-provided Core project state' >&2; exit 78; fi; "
            f"{shlex.join(arguments)} </dev/null | tee {output}"
        )
        await self.exec_as_agent(environment, command=command, env=env, cwd="/app")


__all__ = ["CoreCodeAgent"]
