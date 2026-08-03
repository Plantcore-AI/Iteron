from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core_code_agent import CoreCodeAgent, _split_model_route


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

    async def upload_file(self, source: Path, destination: str) -> None:
        self.uploads.append((source, destination))

    async def exec(self, **kwargs: object) -> SimpleNamespace:
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
            root = Path(directory)
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

    def test_install_and_run_preserve_binary_and_output_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = self._agent(root)
            environment = FakeEnvironment()

            asyncio.run(agent.install(environment))
            self.assertEqual(len(environment.uploads), 1)
            upload = environment.uploads[0][1]
            self.assertRegex(upload, r"^/tmp/core-code-upload-[0-9a-f]{32}$")
            install_call = environment.calls[-1]
            install_command = str(install_call["command"])
            self.assertIn("test ! -L", install_command)
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
            self.assertIn("| tee /logs/agent/core.stream.jsonl", run_command)
            self.assertNotIn("2>&1", run_command)
            self.assertNotIn("credential-fixture-value", run_command)


if __name__ == "__main__":
    unittest.main()
