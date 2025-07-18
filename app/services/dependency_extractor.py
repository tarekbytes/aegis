import asyncio
import logging
from pathlib import Path
import shutil
import sys
import tempfile

logger = logging.getLogger(__name__)


class PipToolsInstallError(RuntimeError):
    """Failed to install pip-tools."""


class PipCompileError(RuntimeError):
    """pip-compile failed."""


async def extract_all_dependencies(requirements_content: str) -> str:
    """
    Given requirements.txt content, returns a string with all resolved
    dependencies (direct + transitive) using pip-compile. Fails if compilation fails.
    """
    logger.info(
        f"Starting dependency extraction for requirements: {requirements_content.strip()}"
    )

    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        req_file = Path(temp_dir) / "requirements.txt"
        output_file = Path(temp_dir) / "requirements.lock"

        # Preprocess requirements content to filter out file reference lines
        filtered_lines = []
        for line in requirements_content.splitlines():
            stripped_line = line.strip()
            # Skip empty lines, comments, and file reference lines
            if (
                stripped_line
                and not stripped_line.startswith("#")
                and not stripped_line.startswith("-r")
                and not stripped_line.startswith("--requirement")
                and not stripped_line.startswith("-c")
                and not stripped_line.startswith("--constraint")
                and not stripped_line.startswith("-e")
                and not stripped_line.startswith("--editable")
            ):
                filtered_lines.append(stripped_line)

        filtered_content = "\n".join(filtered_lines)

        # Write filtered requirements.txt
        with req_file.open("w") as f:
            f.write(filtered_content)

        # Cross-platform Python executable
        python_exe = sys.executable

        # Install pip-tools if not available
        proc = await asyncio.create_subprocess_exec(
            python_exe,
            "-m",
            "pip",
            "install",
            "pip-tools",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise PipToolsInstallError(f"Failed to install pip-tools: {err.decode()}")

        # Run pip-compile to resolve dependencies
        proc = await asyncio.create_subprocess_exec(
            python_exe,
            "-m",
            "piptools",
            "compile",
            "--output-file",
            str(output_file),
            str(req_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise PipCompileError(f"pip-compile failed: {err.decode()}")

        # Read the resolved requirements
        with output_file.open() as f:
            resolved_content = f.read()

        logger.info(
            f"Dependency extraction completed. pip-compile output:\n{resolved_content.strip()}"
        )
        return (
            resolved_content
            if resolved_content.endswith("\n")
            else resolved_content + "\n"
        )
    finally:
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir)
