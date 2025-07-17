import asyncio
import tempfile
import os
import shutil
import logging
import sys

logger = logging.getLogger(__name__)

async def extract_all_dependencies(requirements_content: str) -> str:
    """
    Given requirements.txt content, returns a string with all installed packages (direct + transitive)
    in pip freeze format. Fails if extraction fails.
    """
    logger.info(f"Starting dependency extraction for requirements: {requirements_content.strip()}")
    
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        venv_dir = os.path.join(temp_dir, "venv")
        req_file = os.path.join(temp_dir, "requirements.txt")
        
        # Write requirements.txt
        with open(req_file, "w") as f:
            f.write(requirements_content)

        # Cross-platform Python executable
        python_exe = sys.executable

        # Create venv
        proc = await asyncio.create_subprocess_exec(
            python_exe, "-m", "venv", venv_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError("Failed to create virtualenv")

        # Cross-platform pip path
        if os.name == 'nt':  # Windows
            pip_path = os.path.join(venv_dir, "Scripts", "pip.exe")
        else:  # Unix/Linux/macOS
            pip_path = os.path.join(venv_dir, "bin", "pip")

        # Upgrade pip
        proc = await asyncio.create_subprocess_exec(
            pip_path, "install", "--upgrade", "pip",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        # Install requirements
        proc = await asyncio.create_subprocess_exec(
            pip_path, "install", "-r", req_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to install requirements: {err.decode()}")

        # Run pip freeze to get all installed packages
        proc = await asyncio.create_subprocess_exec(
            pip_path, "freeze",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"pip freeze failed: {err.decode()}")
        freeze_output = out.decode()
        logger.info(f"Dependency extraction completed. pip freeze output:\n{freeze_output.strip()}")
        return freeze_output if freeze_output.endswith("\n") else freeze_output + "\n"
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir) 