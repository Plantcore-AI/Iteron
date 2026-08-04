from __future__ import annotations

import asyncio
import contextvars
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core_code_agent import CoreCodeAgent, _split_model_route
from harbor.agents.factory import AgentFactory
from harbor.environments.base import BaseEnvironment
from harbor.models.trial.config import AgentConfig


def _linux_elf(path: Path, machine: int = 62) -> str:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(header)
    return hashlib.sha256(header).hexdigest()


class FakeEnvironment:
    def __init__(self) -> None:
        self.uploads: list[tuple[Path, str]] = []
        self.calls: list[dict[str, object]] = []
        self._persistent_env: dict[str, str] = {}
        self._exec_env_overlays: contextvars.ContextVar[tuple[dict[str, str], ...]] = (
            contextvars.ContextVar("core_test_exec_env_overlays", default=())
        )

    async def upload_file(self, source: Path, destination: str) -> None:
        self.uploads.append((source, destination))

    async def exec(self, **kwargs: object) -> SimpleNamespace:
        kwargs["merged_env"] = BaseEnvironment._merge_env(
            self,
            kwargs.get("env"),  # type: ignore[arg-type]
        )
        self.calls.append(kwargs)
        return SimpleNamespace(return_code=0, stdout="", stderr="")


class CoreCodeAgentTests(unittest.TestCase):
    def _agent(
        self,
        root: Path,
        *,
        extra_env: dict[str, str] | None = None,
        binary_arch: str = "x86_64",
        model_name: str = "openai/test-model",
        **kwargs: object,
    ) -> CoreCodeAgent:
        binary = root / "core-linux"
        digest = _linux_elf(binary)
        return CoreCodeAgent(
            root / "logs",
            binary_path=binary,
            binary_sha256=digest,
            binary_arch=binary_arch,
            model_name=model_name,
            extra_env=extra_env or {"OPENAI_API_KEY": "credential-fixture-value"},
            **kwargs,
        )

    def test_route_is_exact_and_conflicts_fail(self) -> None:
        self.assertEqual(_split_model_route("openai/gpt", None), ("openai", "gpt"))
        self.assertEqual(_split_model_route("openai/gpt", "openai"), ("openai", "gpt"))
        with self.assertRaisesRegex(ValueError, "conflicts"):
            _split_model_route("anthropic/model", "openai")

    def test_constructor_rejects_nonhermetic_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(ValueError, "exactly"):
                self._agent(
                    root,
                    extra_env={
                        "OPENAI_API_KEY": "credential-fixture-value",
                        "HOME": "/host-home",
                    },
                )
            with self.assertRaisesRegex(ValueError, "exactly"):
                self._agent(root, extra_env={"ANTHROPIC_API_KEY": "value"})
            with self.assertRaisesRegex(ValueError, "architecture"):
                self._agent(root, binary_arch="aarch64")

    def test_custom_credential_name_cannot_control_harbor_shell_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for dangerous in (
                "BASH_ENV",
                "ENV",
                "LD_PRELOAD",
                "PATH",
                "HOME",
                "CORE_CONFIG_HOME",
                "HTTPS_PROXY",
                "BASH_ENV_API_KEY",
            ):
                with (
                    self.subTest(dangerous=dangerous),
                    self.assertRaisesRegex(ValueError, "HARBOR_CORE"),
                ):
                    self._agent(
                        root,
                        base_url="https://gateway.example/v1",
                        key_env=dangerous,
                        extra_env={dangerous: "credential-fixture-value"},
                    )

            credential_env = "HARBOR_CORE_GATEWAY_API_KEY"
            binary = root / "core-linux"
            digest = _linux_elf(binary)
            config = AgentConfig(
                import_path="core_code_agent:CoreCodeAgent",
                model_name="openai/test-model",
                env={credential_env: "credential-fixture-value"},
                kwargs={
                    "binary_path": str(binary),
                    "binary_sha256": digest,
                    "binary_arch": "x86_64",
                    "base_url": "https://gateway.example/v1",
                    "key_env": credential_env,
                },
            )
            agent = AgentFactory.create_agent_from_config(
                config, logs_dir=root / "logs"
            )
            self.assertIsInstance(agent, CoreCodeAgent)
            environment = FakeEnvironment()
            environment._persistent_env = {"TASK_MARKER": "task"}
            with BaseEnvironment.scoped_exec_env(environment, agent.extra_env):
                asyncio.run(agent.install(environment))
                asyncio.run(agent.run("repair it", environment, object()))

            install_env = environment.calls[0]["merged_env"]
            run_env = environment.calls[1]["merged_env"]
            self.assertEqual(
                install_env,
                {
                    "TASK_MARKER": "task",
                    credential_env: "credential-fixture-value",
                },
            )
            self.assertEqual(
                set(run_env),  # type: ignore[arg-type]
                {"TASK_MARKER", credential_env, "HOME", "CORE_CONFIG_HOME"},
            )
            self.assertNotIn("BASH_ENV", run_env)  # type: ignore[operator]
            self.assertNotIn("LD_PRELOAD", run_env)  # type: ignore[operator]

    def test_binary_snapshot_rejects_parent_symlink_and_survives_source_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            source = real / "core-linux"
            digest = _linux_elf(source)
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "snapshot"):
                CoreCodeAgent(
                    root / "logs",
                    binary_path=linked / source.name,
                    binary_sha256=digest,
                    binary_arch="x86_64",
                    model_name="openai/test-model",
                    extra_env={"OPENAI_API_KEY": "credential-fixture-value"},
                )

            agent = CoreCodeAgent(
                root / "logs",
                binary_path=source,
                binary_sha256=digest,
                binary_arch="x86_64",
                model_name="openai/test-model",
                extra_env={"OPENAI_API_KEY": "credential-fixture-value"},
            )
            source.write_bytes(b"replacement after constructor")
            environment = FakeEnvironment()
            asyncio.run(agent.install(environment))
            uploaded_source, _ = environment.uploads[0]
            self.assertNotEqual(uploaded_source, source)
            self.assertEqual(
                hashlib.sha256(uploaded_source.read_bytes()).hexdigest(), digest
            )

    def test_install_and_run_preserve_binary_and_output_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            agent = self._agent(root)
            environment = FakeEnvironment()

            asyncio.run(agent.install(environment))
            self.assertEqual(len(environment.uploads), 1)
            upload = environment.uploads[0][1]
            self.assertRegex(upload, r"^/tmp/core-code-bin-[0-9a-f]{32}$")
            install_call = environment.calls[-1]
            install_command = str(install_call["command"])
            self.assertIn("exec 9<", install_command)
            self.assertIn("chown 0:0 /proc/self/fd/9", install_command)
            self.assertIn(
                "exec 8> /logs/agent/core-machine-contract.json", install_command
            )
            self.assertIn("--machine-contract", install_command)
            self.assertNotIn("credential-fixture-value", install_command)

            asyncio.run(
                agent.run(
                    "repair the parser; print '$(not-a-command)'",
                    environment,
                    object(),
                )
            )
            run_call = environment.calls[-1]
            run_command = str(run_call["command"])
            self.assertEqual(run_call["cwd"], "/app")
            self.assertEqual(set(run_call["env"]), {"HOME", "CORE_CONFIG_HOME"})
            self.assertIn("refusing task-provided Core project state", run_command)
            self.assertIn("exec 8> /logs/agent/core.stream.jsonl", run_command)
            self.assertIn("| tee /proc/self/fd/8", run_command)
            self.assertNotIn("2>&1", run_command)
            self.assertNotIn("credential-fixture-value", run_command)
            for call in environment.calls:
                syntax = subprocess.run(
                    ["bash", "-n", "-c", str(call["command"])],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(syntax.returncode, 0, syntax.stderr)


if __name__ == "__main__":
    unittest.main()
