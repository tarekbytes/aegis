import unittest
from unittest.mock import MagicMock, AsyncMock
import io
import pytest
from fastapi import HTTPException, UploadFile
from app.routers.projects import validate_requirements_file


def create_mock_upload_file(content: str) -> UploadFile:
    """
    Helper function to create a mock UploadFile for testing.
    """
    file_like_object = io.BytesIO(content.encode('utf-8'))
    mock_upload_file = MagicMock(spec=UploadFile)
    mock_upload_file.file = file_like_object
    mock_upload_file.filename = "requirements.txt"
    return mock_upload_file


@pytest.mark.asyncio
async def test_valid_requirements_file():
    """
    Tests that a correctly formatted requirements file passes validation.
    """
    content = "fastapi==0.70.0\nuvicorn>=0.15.0\n# this is a comment\n\npackaging"
    mock_file = create_mock_upload_file(content)

    result = await validate_requirements_file(mock_file)
    assert result is mock_file


@pytest.mark.asyncio
async def test_invalid_requirements_file_raises_exception():
    """
    Tests that a file with an invalid line raises an HTTPException.
    """
    content = "fastapi==0.70.0\nuvicorn>>0.15.0\npackaging"
    mock_file = create_mock_upload_file(content)

    with pytest.raises(HTTPException) as exc_info:
        await validate_requirements_file(mock_file)

    assert exc_info.value.status_code == 422
    assert "Invalid lines found" in exc_info.value.detail["message"]
    assert "Line 2" in exc_info.value.detail["errors"][0]


@pytest.mark.asyncio
async def test_file_with_comments_and_empty_lines_is_valid():
    """
    Tests that a file containing only comments and empty lines is considered valid.
    """
    content = "# This is a file with only comments\n\n# and empty lines\n"
    mock_file = create_mock_upload_file(content)

    result = await validate_requirements_file(mock_file)
    assert result is mock_file


@pytest.mark.asyncio
async def test_empty_file_is_valid():
    """
    Tests that an empty file is considered valid.
    """
    content = ""
    mock_file = create_mock_upload_file(content)

    result = await validate_requirements_file(mock_file)
    assert result is mock_file 