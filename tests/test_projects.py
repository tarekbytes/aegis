import unittest
from unittest.mock import MagicMock, AsyncMock
import io
import pytest
from fastapi import HTTPException, UploadFile
from packaging.requirements import Requirement
from app.routers.projects import validate_requirements_file


def create_mock_upload_file(content: str) -> UploadFile:
    """
    Helper function to create a mock UploadFile for testing.
    """
    mock_upload_file = MagicMock(spec=UploadFile)
    mock_upload_file.filename = "requirements.txt"
    mock_upload_file.read = AsyncMock(return_value=content.encode("utf-8"))
    return mock_upload_file


@pytest.mark.asyncio
async def test_valid_requirements_file():
    """
    Tests that a correctly formatted requirements file is parsed
    into a list of Requirement objects.
    """
    content = "fastapi==0.70.0\nuvicorn"
    mock_file = create_mock_upload_file(content)
    result = await validate_requirements_file(mock_file)
    assert isinstance(result, list)
    assert len(result) == 2
    assert isinstance(result[0], Requirement)
    assert str(result[0]) == "fastapi==0.70.0"
    assert str(result[1]) == "uvicorn"


@pytest.mark.asyncio
async def test_invalid_requirements_file_syntax():
    """
    Tests that a file with an invalid line raises an HTTPException.
    """
    content = "uvicorn>>0.15.0"
    mock_file = create_mock_upload_file(content)

    with pytest.raises(HTTPException) as exc_info:
        await validate_requirements_file(mock_file)

    assert exc_info.value.status_code == 422
    assert "Invalid requirement on line 1" in exc_info.value.detail


@pytest.mark.asyncio
async def test_requirements_file_with_comments_and_empty_lines():
    """
    Tests that comments and empty lines are correctly ignored.
    """
    content = "# This is a comment\n\nrequests\n   # Another comment"
    mock_file = create_mock_upload_file(content)
    result = await validate_requirements_file(mock_file)
    assert len(result) == 1
    assert str(result[0]) == "requests"


@pytest.mark.asyncio
async def test_empty_requirements_file():
    """
    Tests that an empty file results in an empty list.
    """
    content = ""
    mock_file = create_mock_upload_file(content)
    result = await validate_requirements_file(mock_file)
    assert result == [] 