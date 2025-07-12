import io
from unittest.mock import MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient
from fastapi import UploadFile
from starlette.exceptions import HTTPException
from packaging.requirements import Requirement
import httpx

from app.main import app
from app.routers.projects import validate_requirements_file

client = TestClient(app)


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
    assert len(result) == 3
    assert str(result[0]) == "fastapi==0.70.0"
    assert str(result[1]) == "uvicorn>=0.15.0"
    assert str(result[2]) == "packaging"


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
    assert result == []


@pytest.mark.asyncio
async def test_empty_file_is_valid():
    """
    Tests that an empty file is considered valid.
    """
    content = ""
    mock_file = create_mock_upload_file(content)

    result = await validate_requirements_file(mock_file)
    assert result == []


def test_create_project_success(monkeypatch):
    """
    Tests successful project creation and OSV query.
    """
    mock_osv_response = {"results": []}  # Simulate no vulnerabilities found
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    file_content = "requests==2.24.0\n"
    response = client.post(
        "/projects/",
        data={"name": "Test Project", "description": "A test project"},
        files={"file": ("requirements.txt", file_content, "text/plain")},
    )

    assert response.status_code == 201
    expected_response = {
        "name": "Test Project",
        "description": "A test project",
        "is_vulnerable": False,
    }
    assert response.json() == expected_response
    mock_query.assert_called_once()


def test_create_project_osv_error(monkeypatch):
    """
    Tests error handling when the OSV API returns an error.
    """
    mock_error_response = httpx.Response(
        500, request=httpx.Request("POST", ""), json={"error": "Internal Server Error"}
    )
    mock_query = AsyncMock(
        side_effect=httpx.HTTPStatusError(
            "Server Error", request=mock_error_response.request, response=mock_error_response
        )
    )
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    file_content = "requests==2.24.0\n"
    response = client.post(
        "/projects/",
        data={"name": "Test Project", "description": "A test project"},
        files={"file": ("requirements.txt", file_content, "text/plain")},
    )

    assert response.status_code == 500
    assert "Error from OSV API" in response.json()["detail"]
