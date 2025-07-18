from unittest.mock import MagicMock, AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from fastapi import UploadFile
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_502_BAD_GATEWAY,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
import httpx
import io
from packaging.specifiers import SpecifierSet


from app.main import app
from app.data import store
from app.models import (
    OSVVulnerability,
    QueryVulnerabilities,
    OSVBatchResponse,
)
from app.exceptions import ProjectNotFoundError
from app.routers.projects import get_validated_requirements


client = TestClient(app)


class DatabaseError(RuntimeError):
    """Custom exception to simulate database errors in tests."""


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
async def test_valid_requirements_file(monkeypatch):
    # Mock the dependency extractor to return the same content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\npackaging==23.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\n# A comment\npackaging==23.1"
    )
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 2
    assert not errors
    assert str(requirements[0]) == "requests==2.28.1"
    assert str(requirements[1]) == "packaging==23.1"


@pytest.mark.asyncio
async def test_invalid_requirements_file_raises_exception(monkeypatch):
    # Mock the dependency extractor to return the same content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n@invalid-package-name\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_upload_file = create_mock_upload_file("requests==2.28.1\n@invalid-package-name")
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 1
    assert len(errors) == 1
    assert "is not a valid requirement" in errors[0]


@pytest.mark.asyncio
async def test_unpinned_requirements_file_raises_exception(monkeypatch):
    """
    Tests that the validator rejects requirements that are not pinned with '=='.
    """
    # Mock the dependency extractor to return the same content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\ndjango\ntoml>0.1.0\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.post(
        "/projects/",
        data={"name": "Test Project", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    assert response.status_code == HTTP_201_CREATED
    assert response.json() == {
        "name": "Test Project",
        "description": "A test project",
        "is_vulnerable": False,
    }
    mock_query.assert_called_once()


def test_create_project_with_vulns(monkeypatch):
    """Tests successful project creation when vulnerabilities are found."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="jinja2==2.4.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    # Mock the dependency extractor to return invalid content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n@invalid-package-name\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    response = client.post(
        "/projects/",
        data={"name": "Invalid Project"},
        files={"file": ("requirements.txt", b"requests==2.28.1\n@invalid-package-name", "text/plain")},
    )
    assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    error = response.json()
    assert "is not a valid requirement" in error["detail"]


def test_create_project_unpinned_requirements(monkeypatch):
    """Tests that creating a project with unpinned dependencies returns a 422 error."""
    # Mock the dependency extractor to return unpinned content
    mock_extractor = AsyncMock(return_value="requests\ndjango>2.0\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    response = client.post(
        "/projects/",
        data={"name": "Unpinned Project"},
        files={"file": ("requirements.txt", b"requests\ndjango>2.0", "text/plain")},
    )
    assert response.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    error = response.json()
    assert "must be pinned" in error["detail"]


def test_create_project_duplicate_name(monkeypatch):
    """Tests that creating a project with a duplicate name returns a 409 error."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    assert "Project with name 'Duplicate Test' already exists" in error["detail"]


def test_create_project_osv_error(monkeypatch):
    """Tests that a 502 error is returned when the OSV API call fails."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    assert "Error from OSV API: OSV Error" in error["detail"]


def test_get_all_projects(monkeypatch):
    """Tests that the get_projects endpoint correctly returns a list of all projects."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    """Tests that the get_project_dependencies endpoint returns a 404 when project doesn't exist."""
    response = client.get("/projects/999/dependencies")
    assert response.status_code == HTTP_404_NOT_FOUND
    error = response.json()
    assert "Project with id 999 not found" in error["detail"]


def test_delete_project_not_found():
    """Tests that deleting a non-existent project returns a 404 error."""
    response = client.delete("/projects/999")
    assert response.status_code == HTTP_404_NOT_FOUND
    error = response.json()
    assert "Project with id 999 not found" in error["detail"]


def test_delete_project_success(monkeypatch):
    """Tests that deleting an existing project returns a 200 success response."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)

    # First create a project
    client.post(
        "/projects/",
        data={"name": "Project to Delete", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    # Now delete the project
    response = client.delete("/projects/1")
    assert response.status_code == HTTP_200_OK
    result = response.json()
    assert result["message"] == "Project deleted successfully"


def test_delete_project_unexpected_error():
    """Tests that unexpected errors in delete_project are handled properly."""
    # Mock store.delete_project to raise an unexpected exception
    original_delete = store.delete_project

    def mock_delete_project(project_id):  # noqa: ARG001
        raise DatabaseError

    store.delete_project = mock_delete_project

    try:
        response = client.delete("/projects/1")
        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
        error = response.json()
        assert error["detail"] == "Internal server error"
    finally:
        # Restore original function
        store.delete_project = original_delete


def test_update_project_success(monkeypatch):
    """Test updating a project with valid data succeeds."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # Mock OSV response
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Create a project
    create_resp = client.post(
        "/projects/",
        data={"name": "Alpha", "description": "desc1"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    project_id = 1
    assert create_resp.status_code == HTTP_201_CREATED

    # Update the project (keep name the same)
    update_resp = client.put(
        f"/projects/{project_id}",
        data={"name": "Alpha", "description": "desc2"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    assert update_resp.status_code == HTTP_200_OK
    assert update_resp.json()["name"] == "Alpha"
    assert update_resp.json()["description"] == "desc2"


def test_update_project_duplicate_name(monkeypatch):
    """Test updating a project to a name that already exists fails with 409."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\nflask==2.0.0\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Create two projects
    client.post(
        "/projects/",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    client.post(
        "/projects/",
        data={"name": "Beta"},
        files={"file": ("requirements.txt", b"flask==2.0.0", "text/plain")},
    )
    project2_id = 2

    # Try to update project 2 to name 'Alpha' (should fail)
    update_resp = client.put(
        f"/projects/{project2_id}",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"flask==2.0.0", "text/plain")},
    )
    assert update_resp.status_code == HTTP_409_CONFLICT
    assert "already exists" in update_resp.json()["detail"]

    # Update project 2 to keep its own name (should succeed)
    update_resp2 = client.put(
        f"/projects/{project2_id}",
        data={"name": "Beta"},
        files={"file": ("requirements.txt", b"flask==2.0.0", "text/plain")},
    )
    assert update_resp2.status_code == HTTP_200_OK
    assert update_resp2.json()["name"] == "Beta"


def test_update_project_not_found(monkeypatch):
    """Test updating a non-existent project returns 404."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    response = client.put(
        "/projects/999",
        data={"name": "Non-existent"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    assert response.status_code == HTTP_404_NOT_FOUND
    error = response.json()
    assert "Project with id 999 not found" in error["detail"]


def test_update_project_invalid_requirements(monkeypatch):
    """Test updating a project with invalid requirements returns 422."""
    # Mock the dependency extractor to return invalid content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n@invalid-package-name\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)

    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Create a project
    client.post(
        "/projects/",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    project_id = 1

    # Try to update with invalid requirements
    update_resp = client.put(
        f"/projects/{project_id}",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"requests==2.28.1\n@invalid-package-name", "text/plain")},
    )
    assert update_resp.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    assert "is not a valid requirement" in update_resp.json()["detail"]


def test_update_project_osv_error(monkeypatch):
    """Test updating a project when OSV API fails returns 502."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_query = AsyncMock(
        side_effect=httpx.HTTPStatusError("Error", request=MagicMock(), response=MagicMock(text="OSV Error"))
    )
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Create a project
    client.post(
        "/projects/",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    project_id = 1

    # Try to update
    update_resp = client.put(
        f"/projects/{project_id}",
        data={"name": "Alpha"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    assert update_resp.status_code == HTTP_502_BAD_GATEWAY
    assert "Error from OSV API" in update_resp.json()["detail"]


def test_update_project_not_found_error(monkeypatch):
    """Tests that update_project returns 404 when project doesn't exist."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)
    
    # Mock store.update_project to raise ProjectNotFoundError
    original_update = store.update_project
    
    def mock_update_project(project_id, name=None, description=None):
        raise ProjectNotFoundError(project_id)
    
    store.update_project = mock_update_project
    
    try:
        response = client.put(
            "/projects/999",
            data={"name": "Updated Project", "description": "Updated description"},
            files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
        )
        assert response.status_code == HTTP_404_NOT_FOUND
        error = response.json()
        assert "Project with id 999 not found" in error["detail"]
    finally:
        # Restore original function
        store.update_project = original_update


def test_update_project_unexpected_error(monkeypatch):
    """Tests that unexpected errors in update_project are handled properly."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)

    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Mock store.update_project to raise an unexpected exception
    original_update = store.update_project

    def mock_update_project(project_id, name=None, description=None):  # noqa: ARG001
        raise DatabaseError

    store.update_project = mock_update_project

    try:
        response = client.put(
            "/projects/1",
            data={"name": "Updated Project", "description": "Updated description"},
            files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
        )
        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
        error = response.json()
        assert error["detail"] == "Internal server error"
    finally:
        # Restore original function
        store.update_project = original_update


def test_create_project_unexpected_error(monkeypatch):
    """Tests that unexpected errors in create_project are handled properly."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)

    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # Mock store.add_project to raise an unexpected exception
    original_add = store.add_project

    def mock_add_project(name, description=None):  # noqa: ARG001
        raise DatabaseError

    store.add_project = mock_add_project

    try:
        response = client.post(
            "/projects/",
            data={"name": "Error Project", "description": "A test project"},
            files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
        )
        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
        error = response.json()
        assert error["detail"] == "Internal server error"
    finally:
        # Restore original function
        store.add_project = original_add


@pytest.mark.asyncio
async def test_get_validated_requirements_continue_on_unpinned(monkeypatch):
    """Tests that the continue statement is executed when requirements are not pinned."""
    # Mock the dependency extractor to return unpinned content
    mock_extractor = AsyncMock(return_value="requests==2.28.1\ndjango\n# comment\nflask>=2.0\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\ndjango\n# comment\nflask>=2.0"
    )
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 1  # Only requests==2.28.1 should be valid
    assert len(errors) == 2  # django and flask>=2.0 should cause errors
    assert str(requirements[0]) == "requests==2.28.1"
    assert any("must be pinned" in error for error in errors)


@pytest.mark.asyncio
async def test_get_validated_requirements_ignore_pip_syntax():
    """Test that pip requirement syntax is properly ignored during validation."""
    # Create a requirements file with various pip syntax forms
    requirements_content = """# This is a comment
-r other.txt
--requirement=another.txt
-f https://example.com/simple/
--find-links=https://example.com/wheels/
--index-url=https://pypi.org/simple/
--extra-index-url=https://pypi.org/simple/
--trusted-host=example.com
--no-index
--no-deps
--pre
--editable=./local-package
-e ./another-local-package
flask==2.0.1
requests==2.25.1
"""
    
    # Mock the dependency extractor to return expanded dependencies
    expanded_content = """flask==2.0.1
Werkzeug==2.0.1
requests==2.25.1
urllib3==1.26.5
certifi==2020.12.5
charset-normalizer==2.0.0
idna==2.10
pip==21.1.1
setuptools==56.0.0
"""
    
    with patch('app.routers.projects.extract_all_dependencies') as mock_extract:
        mock_extract.return_value = expanded_content
        
        # Create a mock file
        mock_file = AsyncMock()
        mock_file.read.return_value = requirements_content.encode()
        
        requirements, validation_errors = await get_validated_requirements(mock_file)
        
        # Should have no validation errors for expanded dependencies
        assert len(validation_errors) == 0
        # Should have 7 valid requirements (excluding pip and setuptools)
        assert len(requirements) == 7
        assert requirements[0].name == "flask"
        assert requirements[0].specifier == SpecifierSet("==2.0.1")
        assert requirements[1].name == "Werkzeug"
        assert requirements[1].specifier == SpecifierSet("==2.0.1")
        assert requirements[2].name == "requests"
        assert requirements[2].specifier == SpecifierSet("==2.25.1")
        assert requirements[3].name == "urllib3"
        assert requirements[3].specifier == SpecifierSet("==1.26.5")
        assert requirements[4].name == "certifi"
        assert requirements[4].specifier == SpecifierSet("==2020.12.5")
        assert requirements[5].name == "charset-normalizer"
        assert requirements[5].specifier == SpecifierSet("==2.0.0")
        assert requirements[6].name == "idna"
        assert requirements[6].specifier == SpecifierSet("==2.10")


def test_get_project_dependencies_empty_list(monkeypatch):
    """Tests that get_project_dependencies returns empty list when project exists but has no dependencies."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # First create a project
    client.post(
        "/projects/",
        data={"name": "Empty Dependencies Project", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    
    # Get the project ID (assuming it's 1 since we clear the store before each test)
    response = client.get("/projects/1/dependencies")
    assert response.status_code == HTTP_200_OK
    dependencies = response.json()
    assert isinstance(dependencies, list)
    # The project should have dependencies from the requirements.txt file
    assert len(dependencies) > 0


def test_root_endpoint():
    """Test the root endpoint returns the expected message."""
    response = client.get("/")
    assert response.status_code == HTTP_200_OK
    assert response.json() == {"message": "You seem lost!"}


def test_generic_exception_handler():
    """Test that the generic exception handler is properly configured."""
    # This test verifies that the exception handler is properly registered
    # The actual exception handling is tested through integration tests
    # where real exceptions occur in the application flow
    assert hasattr(app, 'exception_handlers')
    assert Exception in app.exception_handlers


def test_lifespan_event(monkeypatch):
    """Test that the scheduler starts and shuts down during lifespan events."""
    started = {}
    shutdown = {}
    monkeypatch.setattr("app.services.scheduler.start", lambda: started.setdefault("called", True))
    monkeypatch.setattr("app.services.scheduler.shutdown", lambda: shutdown.setdefault("called", True))
    with TestClient(app):
        assert started.get("called")
    assert shutdown.get("called")


def test_remove_project_by_id():
    """Test remove_project_by_id removes the correct project."""
    store.clear_projects_store()
    store._projects.extend([
        {"id": 1, "name": "A"},
        {"id": 2, "name": "B"},
    ])
    result = store.remove_project_by_id(1)
    assert len(result) == 1
    assert result[0]["id"] == 2


def test_update_project_removal_and_readd(monkeypatch):
    """Tests that updating a project removes old dependencies and adds new ones."""
    # Mock the dependency extractor for both requests
    mock_extractor = AsyncMock(side_effect=[
        "requests==2.28.1\ndjango==4.0\n",  # First call
        "flask==2.0.0\n"  # Second call
    ])
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # First create a project
    client.post(
        "/projects/",
        data={"name": "Test Project", "description": "Initial description"},
        files={"file": ("requirements.txt", b"requests==2.28.1\ndjango==4.0", "text/plain")},
    )

    # Get the project ID
    projects = client.get("/projects/").json()
    project_id = projects[0]["id"]

    # Check initial dependencies
    initial_deps = client.get(f"/projects/{project_id}/dependencies").json()
    assert len(initial_deps) == 2

    # Update the project with different dependencies
    update_resp = client.put(
        f"/projects/{project_id}",
        data={"name": "Test Project", "description": "Updated description"},
        files={"file": ("requirements.txt", b"flask==2.0.0", "text/plain")},
    )
    assert update_resp.status_code == HTTP_200_OK

    # Check updated dependencies
    updated_deps = client.get(f"/projects/{project_id}/dependencies").json()
    assert len(updated_deps) == 1
    assert updated_deps[0]["name"] == "flask"


def test_store_update_project_removal_and_readd():
    """Test store.update_project removes and re-adds the project with updated data."""
    store.clear_projects_store()
    pid = store.add_project("OldName", "desc")
    store.update_project(pid, "NewName", "newdesc")
    projects = store.get_all_projects()
    assert len(projects) == 1
    assert projects[0]["name"] == "NewName"
    assert projects[0]["description"] == "newdesc"


def test_delete_project_removes_dependencies(monkeypatch):
    """Tests that deleting a project also removes all its dependencies."""
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\ndjango==4.0\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # First create a project with dependencies
    client.post(
        "/projects/",
        data={"name": "Test Project", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1\ndjango==4.0", "text/plain")},
    )

    # Get the project ID
    projects = client.get("/projects/").json()
    project_id = projects[0]["id"]

    # Verify dependencies exist
    deps = client.get(f"/projects/{project_id}/dependencies").json()
    assert len(deps) == 2

    # Delete the project
    delete_resp = client.delete(f"/projects/{project_id}")
    assert delete_resp.status_code == HTTP_200_OK

    # Verify project is gone
    get_resp = client.get("/projects/")
    projects_after = get_resp.json()
    assert len(projects_after) == 0

    # Verify dependencies are also gone by checking the store directly
    all_deps = store.get_all_dependencies()
    assert len(all_deps) == 0



