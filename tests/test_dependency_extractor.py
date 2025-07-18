import sys
from unittest.mock import AsyncMock, mock_open, patch

import pytest

from app.services.dependency_extractor import (
    PipCompileError,
    PipToolsInstallError,
    extract_all_dependencies,
)


class TestDependencyExtractor:
    """Test the dependency extractor service with various dependency specifiers."""

    @pytest.mark.asyncio
    async def test_single_pinned_dependency(self):
        """Test extraction with a single pinned dependency."""
        requirements = "requests==2.31.0"

        # Mock the subprocess calls to return expected pip-compile output
        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            # Verify the result contains the expected dependencies
            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_single_unpinned_dependency(self):
        """Test extraction with a single unpinned dependency."""
        requirements = "requests"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_dependency_with_version_range(self):
        """Test extraction with a dependency that has a version range."""
        requirements = "requests>=2.25.0,<3.0.0"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_dependency_with_extra_requirements(self):
        """Test extraction with a dependency that has extra requirements."""
        requirements = "requests[security]"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\ncryptography==41.0.3\nidna==3.4\npyOpenSSL==23.2.0\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "cryptography==41.0.3" in result
            assert "pyOpenSSL==23.2.0" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_multiple_dependencies(self):
        """Test extraction with multiple dependencies."""
        requirements = "requests==2.31.0\nflask==2.3.3"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="blinker==1.6.2\ncertifi==2023.7.22\ncharset-normalizer==3.2.0\nclick==8.1.7\nflask==2.3.3\nidna==3.4\nitsdangerous==2.1.2\njinja2==3.1.2\nmarkupsafe==2.1.3\nrequests==2.31.0\nurllib3==2.0.4\nwerkzeug==2.3.7\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "flask==2.3.3" in result
            assert "blinker==1.6.2" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "click==8.1.7" in result
            assert "idna==3.4" in result
            assert "itsdangerous==2.1.2" in result
            assert "jinja2==3.1.2" in result
            assert "markupsafe==2.1.3" in result
            assert "urllib3==2.0.4" in result
            assert "werkzeug==2.3.7" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_dependency_with_comments(self):
        """Test extraction with requirements that include comments."""
        requirements = "# This is a comment\nrequests==2.31.0  # Another comment"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_dependency_with_blank_lines(self):
        """Test extraction with requirements that include blank lines."""
        requirements = "requests==2.31.0\n\nflask==2.3.3"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="blinker==1.6.2\ncertifi==2023.7.22\ncharset-normalizer==3.2.0\nclick==8.1.7\nflask==2.3.3\nidna==3.4\nitsdangerous==2.1.2\njinja2==3.1.2\nmarkupsafe==2.1.3\nrequests==2.31.0\nurllib3==2.0.4\nwerkzeug==2.3.7\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "flask==2.3.3" in result
            assert "blinker==1.6.2" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "click==8.1.7" in result
            assert "idna==3.4" in result
            assert "itsdangerous==2.1.2" in result
            assert "jinja2==3.1.2" in result
            assert "markupsafe==2.1.3" in result
            assert "urllib3==2.0.4" in result
            assert "werkzeug==2.3.7" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_pip_tools_installation_failure(self):
        """Test handling of pip-tools installation failure."""
        requirements = "requests==2.31.0"

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 1  # Simulate failure
            mock_proc.communicate = AsyncMock(
                return_value=(b"", b"pip-tools installation failed")
            )
            mock_subprocess.return_value = mock_proc

            with pytest.raises(
                PipToolsInstallError,
                match="Failed to install pip-tools: pip-tools installation failed",
            ):
                await extract_all_dependencies(requirements)

    @pytest.mark.asyncio
    async def test_pip_compile_failure(self):
        """Test handling of pip-compile failure."""
        requirements = "nonexistent-package==1.0.0"

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Create separate mock processes for each call
            mock_install_proc = AsyncMock()
            mock_install_proc.returncode = 0
            mock_install_proc.communicate = AsyncMock(return_value=(b"", b""))

            mock_compile_proc = AsyncMock()
            mock_compile_proc.returncode = 1  # Simulate failure
            mock_compile_proc.communicate = AsyncMock(
                return_value=(
                    b"",
                    b"ERROR: Could not find a version that satisfies the requirement nonexistent-package==1.0.0",
                )
            )

            # Set up the mock to return different processes for different calls
            mock_subprocess.side_effect = [mock_install_proc, mock_compile_proc]

            with pytest.raises(
                PipCompileError,
                match="pip-compile failed: ERROR: Could not find a version that satisfies the requirement nonexistent-package==1.0.0",
            ):
                await extract_all_dependencies(requirements)

    @pytest.mark.asyncio
    async def test_empty_requirements(self):
        """Test extraction with empty requirements."""
        requirements = ""

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch("pathlib.Path.open", mock_open(read_data="")),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert result == "\n"

    @pytest.mark.asyncio
    async def test_pip_compile_output_without_newline(self):
        """
        Test that the function handles pip-compile output
        that doesn't end with newline.
        """
        requirements = "requests==2.31.0"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_windows_pip_path(self):
        """Test that the function uses correct Python executable on Windows."""
        requirements = "requests==2.31.0"

        with (
            patch("asyncio.create_subprocess_exec") as mock_subprocess,
            patch(
                "pathlib.Path.open",
                mock_open(
                    read_data="certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n"
                ),
            ),
        ):
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc

            result = await extract_all_dependencies(requirements)

            # Verify that the subprocess was called with the correct arguments
            # The first call should be for pip-tools installation
            # The second call should be for pip-compile
            assert mock_subprocess.call_count == 2

            # Check that both calls use sys.executable (which is the correct behavior)
            # This is what the Windows-specific logic ensures
            for call_args in mock_subprocess.call_args_list:
                assert (
                    call_args[0][0] == sys.executable
                )  # First argument should be Python executable

            assert "requests==2.31.0" in result
            assert "certifi==2023.7.22" in result
            assert "charset-normalizer==3.2.0" in result
            assert "idna==3.4" in result
            assert "urllib3==2.0.4" in result
            assert result.endswith("\n")

    @pytest.mark.asyncio
    async def test_pip_compile_failure_with_error_message(self):
        """Test that pip-compile failures are properly handled."""
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            # Mock successful pip-tools installation
            mock_install_proc = AsyncMock()
            mock_install_proc.communicate.return_value = (b"", b"")
            mock_install_proc.returncode = 0

            # Mock failed pip-compile
            mock_compile_proc = AsyncMock()
            mock_compile_proc.communicate.return_value = (b"", b"Permission denied")
            mock_compile_proc.returncode = 1

            mock_subprocess.side_effect = [mock_install_proc, mock_compile_proc]

            with pytest.raises(PipCompileError):
                await extract_all_dependencies("flask==2.0.1")
