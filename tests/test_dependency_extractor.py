import pytest
from unittest.mock import patch, AsyncMock
from app.services.dependency_extractor import extract_all_dependencies


class TestDependencyExtractor:
    """Test the dependency extractor service with various dependency specifiers."""

    @pytest.mark.asyncio
    async def test_single_pinned_dependency(self):
        """Test extraction with a single pinned dependency."""
        requirements = "requests==2.31.0"
        
        # Mock the subprocess calls to return expected pip freeze output
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock venv creation
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for requests==2.31.0
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for latest requests
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for requests in the specified range
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for requests with security extras
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\ncryptography==41.0.3\nidna==3.4\npyOpenSSL==23.2.0\nrequests==2.31.0\nurllib3==2.0.4\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for multiple packages
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"blinker==1.6.2\ncertifi==2023.7.22\ncharset-normalizer==3.2.0\nclick==8.1.7\nflask==2.3.3\nidna==3.4\nitsdangerous==2.1.2\njinja2==3.1.2\nmarkupsafe==2.1.3\nrequests==2.31.0\nurllib3==2.0.4\nwerkzeug==2.3.7\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4\n", b"")  # pip freeze
            ]
            
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
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"blinker==1.6.2\ncertifi==2023.7.22\ncharset-normalizer==3.2.0\nclick==8.1.7\nflask==2.3.3\nidna==3.4\nitsdangerous==2.1.2\njinja2==3.1.2\nmarkupsafe==2.1.3\nrequests==2.31.0\nurllib3==2.0.4\nwerkzeug==2.3.7\n", b"")  # pip freeze
            ]
            
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
    async def test_venv_creation_failure(self):
        """Test handling of virtual environment creation failure."""
        requirements = "requests==2.31.0"
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 1  # Simulate failure
            mock_proc.communicate = AsyncMock(return_value=(b"", b"venv creation failed"))
            mock_subprocess.return_value = mock_proc
            
            with pytest.raises(RuntimeError, match="Failed to create virtualenv"):
                await extract_all_dependencies(requirements)

    @pytest.mark.asyncio
    async def test_pip_install_failure(self):
        """Test handling of pip install failure."""
        requirements = "nonexistent-package==1.0.0"
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Create separate mock processes for each call
            mock_venv_proc = AsyncMock()
            mock_venv_proc.returncode = 0
            mock_venv_proc.communicate = AsyncMock(return_value=(b"", b""))
            
            mock_pip_upgrade_proc = AsyncMock()
            mock_pip_upgrade_proc.returncode = 0
            mock_pip_upgrade_proc.communicate = AsyncMock(return_value=(b"", b""))
            
            mock_pip_install_proc = AsyncMock()
            mock_pip_install_proc.returncode = 1  # Simulate failure
            mock_pip_install_proc.communicate = AsyncMock(return_value=(b"", b"ERROR: Could not find a version that satisfies the requirement nonexistent-package==1.0.0"))
            
            # Set up the mock to return different processes for different calls
            mock_subprocess.side_effect = [mock_venv_proc, mock_pip_upgrade_proc, mock_pip_install_proc]
            
            with pytest.raises(RuntimeError, match="Failed to install requirements"):
                await extract_all_dependencies(requirements)

    @pytest.mark.asyncio
    async def test_pip_freeze_failure(self):
        """Test handling of pip freeze failure."""
        requirements = "requests==2.31.0"
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Create separate mock processes for each call
            mock_venv_proc = AsyncMock()
            mock_venv_proc.returncode = 0
            mock_venv_proc.communicate = AsyncMock(return_value=(b"", b""))
            
            mock_pip_upgrade_proc = AsyncMock()
            mock_pip_upgrade_proc.returncode = 0
            mock_pip_upgrade_proc.communicate = AsyncMock(return_value=(b"", b""))
            
            mock_pip_install_proc = AsyncMock()
            mock_pip_install_proc.returncode = 0
            mock_pip_install_proc.communicate = AsyncMock(return_value=(b"", b""))
            
            mock_pip_freeze_proc = AsyncMock()
            mock_pip_freeze_proc.returncode = 1  # Simulate failure
            mock_pip_freeze_proc.communicate = AsyncMock(return_value=(b"", b"pip freeze failed"))
            
            # Set up the mock to return different processes for different calls
            mock_subprocess.side_effect = [mock_venv_proc, mock_pip_upgrade_proc, mock_pip_install_proc, mock_pip_freeze_proc]
            
            with pytest.raises(RuntimeError, match="pip freeze failed"):
                await extract_all_dependencies(requirements)

    @pytest.mark.asyncio
    async def test_empty_requirements(self):
        """Test extraction with empty requirements."""
        requirements = ""
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output for empty environment
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"", b""),  # pip freeze (empty)
            ]
            
            result = await extract_all_dependencies(requirements)
            
            assert result == "\n"  # Should return just a newline for empty output

    @pytest.mark.asyncio
    async def test_pip_freeze_output_without_newline(self):
        """Test that the function handles pip freeze output that doesn't end with newline."""
        requirements = "requests==2.31.0"
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_subprocess.return_value = mock_proc
            
            # Mock pip freeze output without trailing newline
            mock_proc.communicate.side_effect = [
                (b"", b""),  # venv creation
                (b"", b""),  # pip upgrade
                (b"", b""),  # pip install
                (b"certifi==2023.7.22\ncharset-normalizer==3.2.0\nidna==3.4\nrequests==2.31.0\nurllib3==2.0.4", b"")  # pip freeze without newline
            ]
            
            result = await extract_all_dependencies(requirements)
            
            assert "requests==2.31.0" in result
            assert result.endswith("\n")  # Should add newline if missing 