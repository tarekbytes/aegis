import io
from unittest.mock import MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient
from fastapi import UploadFile
from starlette.exceptions import HTTPException
from starlette.status import HTTP_502_BAD_GATEWAY
from packaging.requirements import Requirement
import httpx

from app.main import app
from app.data import store
from app.models import (
    OSVBatchResponse,
    QueryVulnerabilities,
    OSVAbbreviatedVulnerability,
)
from app.models.dependency import Dependency
from app.routers.projects import validate_requirements_file

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_store():
    """
    A fixture that automatically clears the in-memory stores before each test.
    """
    store.clear_projects_store()
    store.clear_dependencies_store()


def create_mock_upload_file(content: str) -> UploadFile:
    """
    Creates a mock UploadFile for testing purposes.
    """
    mock_file = io.BytesIO(content.encode("utf-8"))
    return UploadFile(filename="requirements.txt", file=mock_file)


@pytest.mark.asyncio
async def test_valid_requirements_file():
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\n# A comment\npackaging"
    )
    result = await validate_requirements_file(mock_upload_file)
    assert len(result) == 2
    assert str(result[0]) == "requests==2.28.1"
    assert str(result[1]) == "packaging"


@pytest.mark.asyncio
async def test_invalid_requirements_file_raises_exception():
    mock_upload_file = create_mock_upload_file("requests==2.28.1\n-r other.txt")
    with pytest.raises(HTTPException) as exc_info:
        await validate_requirements_file(mock_upload_file)
    assert exc_info.value.status_code == 422
    assert "Line 2" in exc_info.value.detail["errors"][0]


def test_create_project_no_vulns(monkeypatch):
    """
    Tests successful project creation when no vulnerabilities are found.
    """
    mock_osv_response = OSVBatchResponse(
        results=[QueryVulnerabilities(vulns=[])]
    )
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

    # Verify data was stored correctly
    deps = store.get_dependencies_by_project_id(1)
    assert len(deps) == 1
    assert deps[0]["name"] == "requests"
    assert deps[0]["version"] == "2.28.1"
    assert not deps[0]["is_vulnerable"]
    assert len(deps[0]["vulnerability_ids"]) == 0


def test_create_project_with_vulns(monkeypatch):
    """
    Tests successful project creation when vulnerabilities are found.
    """
    # This is an abbreviated OSV object, as returned by the querybatch endpoint
    mock_osv_response = OSVBatchResponse(
        results=[
            QueryVulnerabilities(
                vulns=[
                    OSVAbbreviatedVulnerability(
                        id="GHSA-1234", modified="2023-01-01T00:00:00Z"
                    )
                ]
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

    assert response.status_code == 201
    assert response.json()["is_vulnerable"] is True
    mock_query.assert_called_once()

    # Verify data was stored correctly
    deps = store.get_dependencies_by_project_id(1)
    assert len(deps) == 1
    assert deps[0]["name"] == "jinja2"
    assert deps[0]["version"] == "2.4.1"
    assert deps[0]["is_vulnerable"]
    assert deps[0]["vulnerability_ids"] == ["GHSA-1234"]


def test_create_project_osv_error(monkeypatch):
    """
    Tests that a 502 error is returned when the OSV API call fails.
    """
    mock_query = AsyncMock(
        side_effect=httpx.HTTPStatusError(
            "Error", request=MagicMock(), response=MagicMock(text="OSV Error")
        )
    )
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.post(
        "/projects/",
        data={"name": "Error Project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    assert response.status_code == HTTP_502_BAD_GATEWAY
    mock_query.assert_called_once()


def test_get_all_projects(monkeypatch):
    """
    Tests that the get_projects endpoint correctly returns a list of all projects.
    """
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # 1. Create a project
    client.post(
        "/projects/",
        data={"name": "My First Project", "description": "A description"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    # 2. Get all projects
    response = client.get("/projects/")
    assert response.status_code == 200
    projects = response.json()
    assert len(projects) == 1
    assert projects[0]["id"] == 1
    assert projects[0]["name"] == "My First Project"
    assert projects[0]["description"] == "A description"


def test_get_project_dependencies(monkeypatch):
    """
    Tests that the get_project_dependencies endpoint returns the correct data.
    """
    # 1. Mock the OSV response to create a project with known dependencies
    mock_osv_response = OSVBatchResponse(
        results=[
            QueryVulnerabilities(vulns=[]),  # First dep is clean
            QueryVulnerabilities(
                vulns=[
                    OSVAbbreviatedVulnerability(
                        id="GHSA-5678", modified="2023-01-01T00:00:00Z"
                    )
                ]
            ),
        ]
    )
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # 2. Create the project
    project_name = "Project With Dependencies"
    client.post(
        "/projects/",
        data={"name": project_name},
        files={
            "file": ("requirements.txt", b"requests==2.28.1\njinja2==2.4.1", "text/plain")
        },
    )

    # 3. Get the ID of the project we just created
    response = client.get("/projects/")
    projects = response.json()
    project_id = next(p["id"] for p in projects if p["name"] == project_name)

    # 4. Call the new endpoint and verify the response
    response = client.get(f"/projects/{project_id}/dependencies")
    assert response.status_code == 200
    dependencies = response.json()
    assert len(dependencies) == 2

    assert dependencies[0]["name"] == "requests"
    assert dependencies[0]["version"] == "2.28.1"
    assert dependencies[0]["is_vulnerable"] is False

    assert dependencies[1]["name"] == "jinja2"
    assert dependencies[1]["version"] == "2.4.1"
    assert dependencies[1]["is_vulnerable"] is True
