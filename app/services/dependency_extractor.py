import asyncio
import tempfile
import os
import shutil
import logging
import sys

logger = logging.getLogger(__name__)

async def extract_all_dependencies(requirements_content: str) -> str:
    """
    Given requirements.txt content, returns a string with all resolved dependencies (direct + transitive)
    using pip-compile. Fails if compilation fails.
    """
    logger.info(f"Starting dependency extraction for requirements: {requirements_content.strip()}")
    
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        req_file = os.path.join(temp_dir, "requirements.txt")
        output_file = os.path.join(temp_dir, "requirements.lock")
        
        # Preprocess requirements content to filter out file reference lines
        filtered_lines = []
        for line in requirements_content.splitlines():
            line = line.strip()
            # Skip empty lines, comments, and file reference lines
            if (line and 
                not line.startswith("#") and 
                not line.startswith("-r") and
                not line.startswith("--requirement") and
                not line.startswith("-c") and
                not line.startswith("--constraint") and
                not line.startswith("-e") and
                not line.startswith("--editable")):
                filtered_lines.append(line)
        
        filtered_content = "\n".join(filtered_lines)
        
        # Write filtered requirements.txt
        with open(req_file, "w") as f:
            f.write(filtered_content)

        # Cross-platform Python executable
        python_exe = sys.executable

        # Install pip-tools if not available
        proc = await asyncio.create_subprocess_exec(
            python_exe, "-m", "pip", "install", "pip-tools",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to install pip-tools: {err.decode()}")

        # Run pip-compile to resolve dependencies
        proc = await asyncio.create_subprocess_exec(
            python_exe, "-m", "piptools", "compile", 
            "--output-file", output_file,
            req_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"pip-compile failed: {err.decode()}")

        # Read the resolved requirements
        with open(output_file, "r") as f:
            resolved_content = f.read()
        
        logger.info(f"Dependency extraction completed. pip-compile output:\n{resolved_content.strip()}")
        return resolved_content if resolved_content.endswith("\n") else resolved_content + "\n"
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir) 