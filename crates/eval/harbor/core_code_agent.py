"""Pinned Harbor installed-agent adapter for the Core Code CLI.

This module intentionally does not download an unversioned release.  The caller
supplies one host-side Linux binary and its SHA-256; Harbor uploads those exact
bytes into every fresh task environment.  Import it with Harbor's custom-agent
surface, for example ``core_code_agent:CoreCodeAgent``.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shlex
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from harbor.agents.installed.base import BaseInstalledAgent, with_prompt_template
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext
from harbor.models.trial.paths import EnvironmentPaths

_MAX_BINARY_BYTES = 256 * 1024 * 1024
_SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_CREDENTIAL_ENV_RE = re.compile(
    r"HARBOR_CORE_[A-Z0-9]{1,32}_(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|TOKEN|SECRET|CREDENTIAL)\Z"
)
_BUILTIN_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "glm": "GLM_API_KEY",
    "minimax": "MINIMAX_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
}
_ELF_MACHINES = {62: "x86_64", 183: "aarch64"}


def _normalize_sha256(value: str) -> str:
    match = _SHA256_RE.fullmatch(value)
    if match is None:
        raise ValueError("binary_sha256 must be 64 lowercase hex digits")
    return match.group(1)


def _linux_binary_arch(header: bytes) -> str:
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


def _open_binary_without_symlinks(path: Path) -> int:
    """Open one absolute regular-file candidate without following any component."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise ValueError("host does not support no-follow binary snapshotting")
    if not path.is_absolute() or not path.name or ".." in path.parts:
        raise ValueError("binary_path must be an absolute normalized file path")

    common = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    directory_fd = os.open(path.anchor, common | directory)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, common | directory, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(path.name, common, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def _snapshot_binary(
    path: Path, expected_sha256: str, expected_arch: str
) -> tuple[tempfile.TemporaryDirectory[str], Path, int]:
    snapshot_root = tempfile.TemporaryDirectory(prefix="core-harbor-binary-")
    snapshot = Path(snapshot_root.name) / "core"
    try:
        descriptor = _open_binary_without_symlinks(path)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("binary_path must be a regular non-symlink file")
            if metadata.st_size <= 0 or metadata.st_size > _MAX_BINARY_BYTES:
                raise ValueError(
                    f"Core binary must contain 1..={_MAX_BINARY_BYTES} bytes"
                )
            digest = hashlib.sha256()
            header = bytearray()
            remaining = metadata.st_size
            with snapshot.open("xb") as destination:
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Core binary changed while being snapshotted")
                    if len(header) < 20:
                        header.extend(chunk[: 20 - len(header)])
                    digest.update(chunk)
                    destination.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError("Core binary grew while being snapshotted")
                destination.flush()
                os.fsync(destination.fileno())
            after = os.fstat(source.fileno())
            before_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if after_identity != before_identity:
                raise ValueError("Core binary changed while being snapshotted")
        if digest.hexdigest() != expected_sha256:
            raise ValueError("Core binary SHA-256 does not match binary_sha256")
        actual_arch = _linux_binary_arch(bytes(header))
        if actual_arch != expected_arch:
            raise ValueError("Core ELF architecture does not match binary_arch")
        snapshot.chmod(0o400)
        return snapshot_root, snapshot, metadata.st_size
    except Exception:
        snapshot_root.cleanup()
        raise


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
        self._binary_sha256 = _normalize_sha256(binary_sha256)
        if binary_arch not in set(_ELF_MACHINES.values()):
            raise ValueError("binary_arch must be x86_64 or aarch64")
        try:
            (
                self._binary_snapshot_root,
                self._binary_path,
                self._binary_size,
            ) = _snapshot_binary(path, self._binary_sha256, binary_arch)
        except OSError as error:
            raise ValueError(f"cannot snapshot Core binary: {error}") from error

        if not 1 <= max_turns <= 100_000:
            raise ValueError("max_turns must be in 1..=100000")
        if not 1 <= max_wall_secs <= 86_400:
            raise ValueError("max_wall_secs must be in 1..=86400")
        if effort not in {None, "low", "medium", "high", "xhigh", "max", "ultracode"}:
            raise ValueError("effort is not a supported Core effort level")
        if (base_url is None) != (key_env is None):
            raise ValueError("base_url and key_env must be supplied together")
        if key_env is not None and _CREDENTIAL_ENV_RE.fullmatch(key_env) is None:
            raise ValueError("key_env must use HARBOR_CORE_<LABEL>_<SENSITIVE_SUFFIX>")
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
        self._remote_binary = PurePosixPath(f"/tmp/core-code-bin-{nonce}")
        self._remote_home = PurePosixPath(f"/tmp/core-harbor-home-{nonce}")
        self._remote_config_home = PurePosixPath(f"/tmp/core-harbor-config-{nonce}")

    def close(self) -> None:
        """Remove the private host snapshot when this adapter is no longer used."""
        snapshot_root = getattr(self, "_binary_snapshot_root", None)
        if snapshot_root is not None:
            snapshot_root.cleanup()
            self._binary_snapshot_root = None

    def __del__(self) -> None:
        self.close()

    @staticmethod
    def name() -> str:
        return "core-code"

    def get_version_command(self) -> str | None:
        binary = shlex.quote(self._remote_binary.as_posix())
        expected = shlex.quote(self._binary_sha256)
        return (
            f"set -eu; exec 9< {binary}; "
            f'test "$(stat -Lc %s /proc/self/fd/9)" -eq {self._binary_size}; '
            "actual=$(sha256sum /proc/self/fd/9 | awk '{print $1}'); "
            f'test "$actual" = {expected}; /proc/self/fd/9 --version'
        )

    def parse_version(self, stdout: str) -> str:
        return stdout.strip()

    async def install(self, environment: BaseEnvironment) -> None:
        await environment.upload_file(self._binary_path, self._remote_binary.as_posix())
        expected = shlex.quote(self._binary_sha256)
        binary = shlex.quote(self._remote_binary.as_posix())
        contract = shlex.quote(
            (EnvironmentPaths.agent_dir / "core-machine-contract.json").as_posix()
        )
        credential_env = shlex.quote(self._credential_env)
        await self.exec_as_root(
            environment,
            command=(
                f"set -euC; unset {credential_env}; umask 077; "
                f"exec 9< {binary}; test -f /proc/self/fd/9; "
                f'test "$(stat -Lc %s /proc/self/fd/9)" -eq {self._binary_size}; '
                "actual=$(sha256sum /proc/self/fd/9 | awk '{print $1}'); "
                f'test "$actual" = {expected}; '
                "chown 0:0 /proc/self/fd/9; chmod 0555 /proc/self/fd/9; "
                f"exec 8> {contract}; "
                "/proc/self/fd/9 --machine-contract >&8"
            ),
        )

    @with_prompt_template
    async def run(
        self, instruction: str, environment: BaseEnvironment, context: AgentContext
    ) -> None:
        del context
        assert self.model_name is not None
        provider, model = _split_model_route(self.model_name, self._provider)
        binary = self._remote_binary.as_posix()

        arguments = [
            "/proc/self/fd/9",
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
        expected = shlex.quote(self._binary_sha256)
        command = (
            "set -euC; umask 077; "
            f"mkdir -m 0700 {shlex.quote(self._remote_home.as_posix())} "
            f"{shlex.quote(self._remote_config_home.as_posix())} "
            f"{shlex.quote(runs.as_posix())}; exec 8> {output}; "
            f"exec 9< {shlex.quote(binary)}; test -f /proc/self/fd/9; "
            f'test "$(stat -Lc %s /proc/self/fd/9)" -eq {self._binary_size}; '
            "actual=$(sha256sum /proc/self/fd/9 | awk '{print $1}'); "
            f'test "$actual" = {expected}; '
            "if [ -e /app/.core ] || [ -L /app/.core ]; then "
            "echo 'refusing task-provided Core project state' >&2; exit 78; fi; "
            f"{shlex.join(arguments)} </dev/null | tee /proc/self/fd/8"
        )
        await self.exec_as_agent(environment, command=command, env=env, cwd="/app")


__all__ = ["CoreCodeAgent"]
