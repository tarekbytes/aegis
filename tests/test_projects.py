from unittest.mock import MagicMock, AsyncMock
import pytest
from fastapi.testclient import TestClient
from fastapi import UploadFile, HTTPException
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_502_BAD_GATEWAY,
)
import httpx
import io

from app.main import app
from app.data import store
from app.models import (
    OSVVulnerability,
    QueryVulnerabilities,
    OSVBatchResponse,
)
from app.routers.projects import get_validated_requirements


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_store():
    """A fixture that automatically clears the in-memory stores before each test."""
    store.clear_projects_store()
    store.clear_dependencies_store()


def create_mock_upload_file(content: str) -> UploadFile:
    """Creates a mock UploadFile for testing purposes."""
    mock_file = io.BytesIO(content.encode("utf-8"))
    return UploadFile(filename="requirements.txt", file=mock_file)


@pytest.mark.asyncio
async def test_valid_requirements_file():
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\n# A comment\npackaging==23.1"
    )
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 2
    assert not errors
    assert str(requirements[0]) == "requests==2.28.1"
    assert str(requirements[1]) == "packaging==23.1"


@pytest.mark.asyncio
async def test_invalid_requirements_file_raises_exception():
    mock_upload_file = create_mock_upload_file("requests==2.28.1\n-r other.txt")
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 1
    assert len(errors) == 1
    assert "is not a valid requirement" in errors[0]


@pytest.mark.asyncio
async def test_unpinned_requirements_file_raises_exception():
    """
    Tests that the validator rejects requirements that are not pinned with '=='.
    """
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\ndjango\ntoml>0.1.0"
    )
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 1
    assert len(errors) == 2
    assert "must be pinned" in errors[0]
    assert "must be pinned" in errors[1]


def test_create_project_no_vulns(monkeypatch):
    """Tests successful project creation when no vulnerabilities are found."""
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.post(
        "/projects/",
        data={"name": "Test Project", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    assert response.status_code == 201
    assert response.json() == {
        "name": "Test Project",
        "description": "A test project",
        "is_vulnerable": False,
    }
    mock_query.assert_called_once()


def test_create_project_with_vulns(monkeypatch):
    """Tests successful project creation when vulnerabilities are found."""
    mock_osv_response = OSVBatchResponse(
        results=[
            QueryVulnerabilities(
                vulns=[OSVVulnerability(id="GHSA-1234", modified="2023-01-01T00:00:00Z")]
            )
        ]
    )
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.post(
        "/projects/",
        data={"name": "Vulnerable Project"},
        files={"file": ("requirements.txt", b"jinja2==2.4.1", "text/plain")},
    )

    assert response.status_code == HTTP_201_CREATED
    project_data = response.json()
    assert project_data["name"] == "Vulnerable Project"
    assert project_data["is_vulnerable"] is True


def test_create_project_invalid_requirements(monkeypatch):
    """Tests that creating a project with an invalid requirements file returns a 422 error."""
    response = client.post(
        "/projects/",
        data={"name": "Invalid Project"},
        files={"file": ("requirements.txt", b"requests==2.28.1\n-r other.txt", "text/plain")},
    )
    assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    error = response.json()
    assert error["name"] == "ValidationError"
    assert "is not a valid requirement" in error["description"]


def test_create_project_unpinned_requirements(monkeypatch):
    """Tests that creating a project with unpinned dependencies returns a 422 error."""
    response = client.post(
        "/projects/",
        data={"name": "Unpinned Project"},
        files={"file": ("requirements.txt", b"requests\ndjango>2.0", "text/plain")},
    )
    assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    error = response.json()
    assert error["name"] == "ValidationError"
    assert "must be pinned" in error["description"]


def test_create_project_duplicate_name(monkeypatch):
    """Tests that creating a project with a duplicate name returns a 409 error."""
    client.post(
        "/projects/",
        data={"name": "Duplicate Test", "description": "First instance"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    response = client.post(
        "/projects/",
        data={"name": "Duplicate Test", "description": "Second instance"},
        files={"file": ("requirements.txt", b"django==4.0", "text/plain")},
    )

    assert response.status_code == HTTP_409_CONFLICT
    error = response.json()
    assert error["name"] == "DuplicateProjectError"
    assert "Project with name 'Duplicate Test' already exists" in error["description"]


def test_create_project_osv_error(monkeypatch):
    """Tests that a 502 error is returned when the OSV API call fails."""
    mock_query = AsyncMock(
        side_effect=httpx.HTTPStatusError("Error", request=MagicMock(), response=MagicMock(text="OSV Error"))
    )
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.post(
        "/projects/",
        data={"name": "Error Project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    assert response.status_code == HTTP_502_BAD_GATEWAY
    error = response.json()
    assert error["name"] == "OSVServiceError"
    assert "Error from OSV API: OSV Error" in error["description"]


def test_get_all_projects(monkeypatch):
    """Tests that the get_projects endpoint correctly returns a list of all projects."""
    client.post(
        "/projects/",
        data={"name": "My First Project", "description": "A description"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    response = client.get("/projects/")
    assert response.status_code == HTTP_200_OK
    projects = response.json()
    assert len(projects) == 1
    assert projects[0]["name"] == "My First Project"


def test_get_project_dependencies_not_found():
    """Tests that a 404 error is returned for a non-existent project."""
    response = client.get("/projects/999/dependencies")
    assert response.status_code == HTTP_404_NOT_FOUND
    error = response.json()
    assert error["name"] == "ProjectNotFoundError"
    assert "Project with ID 999 not found" in error["description"]
