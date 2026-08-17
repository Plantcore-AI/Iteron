#!/usr/bin/env python3
"""Render the version-bound installer asset from the repository template."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from common import ReleaseToolError, atomic_write_text, require_regular_file, run_main, validate_version

MARKER = "@ITERON_VERSION@"

# A rendered installer is a published, attested release asset. It is never shipped without the
# interpreter that will run it having parsed it first, so a template edit cannot publish a broken
# `curl | sh` or `irm | iex` surface. PowerShell is only present where PowerShell scripts are
# rendered, which is why the Windows installer is rendered on the Windows release runner.
POSIX_SHELL_SUFFIX = ".sh"
POWERSHELL_SUFFIX = ".ps1"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--template", required=True, type=Path)
    result.add_argument("--version", required=True)
    result.add_argument("--output", required=True, type=Path)
    return result


def render(template: str, version: str) -> str:
    if template.count(MARKER) != 1:
        raise ReleaseToolError("installer template must contain exactly one version marker")
    return template.replace(MARKER, f"v{version}")


def powershell_interpreter() -> str:
    for candidate in ("pwsh", "powershell"):
        if shutil.which(candidate) is not None:
            return candidate
    raise ReleaseToolError(
        "rendering a PowerShell installer requires pwsh or powershell on PATH; "
        "render install.ps1 on the Windows release runner"
    )


def syntax_check(output: Path) -> None:
    """Parse the rendered installer with the interpreter that will execute it."""
    suffix = output.suffix
    if suffix == POSIX_SHELL_SUFFIX:
        command = ["sh", "-n", str(output)]
    elif suffix == POWERSHELL_SUFFIX:
        # The language parser reports syntax errors without executing a single statement, so an
        # installer template can never run during its own validation.
        # The path is embedded in the script rather than passed after it. `-Command` does not
        # populate `$args`; that is `-File` semantics. Anything written after the command string is
        # appended to the command *text*, so the previous spelling turned the path into a stray
        # token and PowerShell answered with `UnexpectedToken` -- reported here as
        # "the file could not be read", because `$args[0]` was empty and `ParseFile` got $null.
        # The Windows installer could therefore never be rendered at all; it went unnoticed because
        # the release leg that renders it only runs on a tag, and no tag has been cut since.
        #
        # Single quotes make the literal inert, and doubling any single quote inside it keeps a
        # path containing one from closing the string early.
        literal = str(output).replace("'", "''")
        script = (
            "$errors = $null; "
            "$null = [System.Management.Automation.Language.Parser]::ParseFile("
            f"'{literal}', [ref]$null, [ref]$errors); "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { "
            "[Console]::Error.WriteLine($_.ToString()) }; exit 1 }"
        )
        command = [powershell_interpreter(), "-NoProfile", "-NonInteractive", "-Command", script]
    else:
        raise ReleaseToolError(f"unsupported installer template type: {suffix!r}")
    check = subprocess.run(command, check=False, capture_output=True, text=True)
    if check.returncode != 0:
        output.unlink(missing_ok=True)
        raise ReleaseToolError(f"rendered installer failed syntax check: {check.stderr.strip()}")


def main() -> None:
    arguments = parser().parse_args()
    version = validate_version(arguments.version)
    require_regular_file(arguments.template, max_bytes=1024 * 1024)
    try:
        template = arguments.template.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseToolError("installer template is not UTF-8") from error
    output = render(template, version)
    atomic_write_text(arguments.output, output, mode=0o755)
    syntax_check(arguments.output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
