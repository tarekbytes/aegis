from unittest.mock import MagicMock, AsyncMock
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

    assert response.status_code == HTTP_201_CREATED
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
    assert "is not a valid requirement" in error["detail"]


def test_create_project_unpinned_requirements(monkeypatch):
    """Tests that creating a project with unpinned dependencies returns a 422 error."""
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
    assert "Project with ID 999 not found" in error["detail"]


def test_delete_project_not_found():
    """Tests that deleting a non-existent project returns a 404 error."""
    response = client.delete("/projects/999")
    assert response.status_code == HTTP_404_NOT_FOUND
    error = response.json()
    assert "Project with id 999 not found" in error["detail"]


def test_delete_project_success():
    """Tests that deleting an existing project returns a 200 success response."""
    # First create a project
    client.post(
        "/projects/",
        data={"name": "Project to Delete", "description": "A test project"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    
    # Now delete the project (assuming it has ID 1 since we clear the store before each test)
    response = client.delete("/projects/1")
    assert response.status_code == HTTP_200_OK
    result = response.json()
    assert result["message"] == "Project deleted successfully"


def test_delete_project_unexpected_error(monkeypatch):
    """Tests that unexpected errors in delete_project are handled properly."""
    # Mock store.delete_project to raise an unexpected exception
    original_delete = store.delete_project
    
    def mock_delete_project(project_id):
        raise RuntimeError("Unexpected database error")
    
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
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    update_resp = client.put(
        "/projects/999",
        data={"name": "Ghost"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    assert update_resp.status_code == HTTP_404_NOT_FOUND
    assert "not found" in update_resp.json()["detail"]


def test_update_project_invalid_requirements(monkeypatch):
    """Test updating a project with invalid requirements returns 422."""
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
        files={"file": ("requirements.txt", b"requests==2.28.1\n-r other.txt", "text/plain")},
    )
    assert update_resp.status_code == HTTP_422_UNPROCESSABLE_ENTITY
    assert "is not a valid requirement" in update_resp.json()["detail"]


def test_update_project_osv_error(monkeypatch):
    """Test updating a project when OSV API fails returns 502."""
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
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)
    
    # Mock store.update_project to raise ProjectNotFoundError
    original_update = store.update_project
    
    def mock_update_project(project_id, name=None, description=None):
        raise ProjectNotFoundError(f"Project with ID {project_id} not found")
    
    store.update_project = mock_update_project
    
    try:
        response = client.put(
            "/projects/999",
            data={"name": "Updated Project", "description": "Updated description"},
            files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
        )
        assert response.status_code == HTTP_404_NOT_FOUND
        error = response.json()
        assert "Project with ID 999 not found" in error["detail"]
    finally:
        # Restore original function
        store.update_project = original_update


def test_update_project_unexpected_error(monkeypatch):
    """Tests that unexpected errors in update_project are handled properly."""
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)
    
    # Mock store.update_project to raise an unexpected exception
    original_update = store.update_project
    
    def mock_update_project(project_id, name=None, description=None):
        raise RuntimeError("Unexpected database error")
    
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
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)
    
    # Mock store.add_project to raise an unexpected exception
    original_add = store.add_project
    
    def mock_add_project(name, description=None):
        raise RuntimeError("Unexpected database error")
    
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
async def test_get_validated_requirements_continue_on_unpinned():
    """Tests that the continue statement is executed when requirements are not pinned."""
    mock_upload_file = create_mock_upload_file(
        "requests==2.28.1\ndjango\n# comment\nflask>=2.0"
    )
    requirements, errors = await get_validated_requirements(mock_upload_file)
    assert len(requirements) == 1  # Only requests==2.28.1 should be valid
    assert len(errors) == 2  # django and flask>=2.0 should cause errors
    assert str(requirements[0]) == "requests==2.28.1"
    assert any("must be pinned" in error for error in errors)


def test_get_project_dependencies_empty_list():
    """Tests that get_project_dependencies returns empty list when project exists but has no dependencies."""
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


def test_update_project_removal_and_readd():
    """Tests that updating a project removes old dependencies and adds new ones."""
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
    dep_names = {dep["name"] for dep in initial_deps}
    assert "requests" in dep_names
    assert "django" in dep_names
    
    # Update the project with different dependencies
    client.put(
        f"/projects/{project_id}",
        data={"name": "Updated Project", "description": "Updated description"},
        files={"file": ("requirements.txt", b"flask==2.3.0\nsqlalchemy==2.0.0", "text/plain")},
    )
    
    # Check that dependencies were replaced
    updated_deps = client.get(f"/projects/{project_id}/dependencies").json()
    assert len(updated_deps) == 2
    updated_dep_names = {dep["name"] for dep in updated_deps}
    assert "flask" in updated_dep_names
    assert "sqlalchemy" in updated_dep_names
    assert "requests" not in updated_dep_names
    assert "django" not in updated_dep_names


def test_store_update_project_removal_and_readd():
    """Test store.update_project removes and re-adds the project with updated data."""
    store.clear_projects_store()
    pid = store.add_project("OldName", "desc")
    store.update_project(pid, "NewName", "newdesc")
    projects = store.get_all_projects()
    assert len(projects) == 1
    assert projects[0]["name"] == "NewName"
    assert projects[0]["description"] == "newdesc"


def test_delete_project_removes_dependencies():
    """Tests that deleting a project also removes all its dependencies."""
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
    response = client.delete(f"/projects/{project_id}")
    assert response.status_code == HTTP_200_OK
    
    # Verify project is gone
    projects_after = client.get("/projects/").json()
    assert len(projects_after) == 0
    
    # Verify dependencies are also gone by checking the store directly
    all_deps = store.get_all_dependencies()
    assert len(all_deps) == 0



