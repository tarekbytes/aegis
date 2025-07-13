from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    OSVBatchResponse,
    QueryVulnerabilities,
    OSVAbbreviatedVulnerability,
)


client = TestClient(app)


def test_get_all_dependencies(monkeypatch):
    """
    Tests that the global GET /dependencies endpoint returns a flat list of
    all dependencies from multiple projects.
    """
    # 1. Mock the OSV response for two separate project creations
    mock_osv_response_1 = OSVBatchResponse(
        results=[QueryVulnerabilities(vulns=[])]
    )
    mock_osv_response_2 = OSVBatchResponse(
        results=[
            QueryVulnerabilities(
                vulns=[
                    OSVAbbreviatedVulnerability(
                        id="GHSA-5678", modified="2023-01-01T00:00:00Z"
                    )
                ]
            )
        ]
    )
    mock_query = AsyncMock(side_effect=[mock_osv_response_1, mock_osv_response_2])
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # 2. Create the first project
    client.post(
        "/projects/",
        data={"name": "Project A"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    # 3. Create the second project
    client.post(
        "/projects/",
        data={"name": "Project B"},
        files={"file": ("requirements.txt", b"jinja2==2.4.1", "text/plain")},
    )

    # 4. Call the global dependencies endpoint and verify the response
    response = client.get("/dependencies/")
    assert response.status_code == 200
    dependencies = response.json()
    assert len(dependencies) == 2

    assert dependencies[0]["name"] == "requests"
    assert dependencies[0]["is_vulnerable"] is False

    assert dependencies[1]["name"] == "jinja2"
    assert dependencies[1]["is_vulnerable"] is True


def test_get_dependency_by_name(monkeypatch):
    """
    Tests that GET /dependencies/{name} returns all versions of a dependency
    if it exists in multiple projects.
    """
    # 1. Mock OSV responses
    mock_osv_response_1 = OSVBatchResponse(
        results=[QueryVulnerabilities(vulns=[])]
    )
    mock_osv_response_2 = OSVBatchResponse(
        results=[QueryVulnerabilities(vulns=[])]
    )
    mock_query = AsyncMock(side_effect=[mock_osv_response_1, mock_osv_response_2])
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # 2. Create two projects with different versions of the same dependency
    client.post(
        "/projects/",
        data={"name": "Project A"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )
    client.post(
        "/projects/",
        data={"name": "Project B"},
        files={"file": ("requirements.txt", b"requests==2.28.2", "text/plain")},
    )

    # 3. Get the dependency by name and verify both versions are returned
    response = client.get("/dependencies/requests")
    assert response.status_code == 200
    details = response.json()
    assert len(details) == 2
    assert {d["version"] for d in details} == {"2.28.1", "2.28.2"}
    assert details[0]["projects"] == ["Project A"]
    assert details[1]["projects"] == ["Project B"]


def test_get_dependency_by_name_and_version(monkeypatch):
    """
    Tests that GET /dependencies/{name}?version={version} returns the
    correct specific version of a dependency.
    """
    # 1. Mock OSV response
    mock_osv_response = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_query = AsyncMock(return_value=mock_osv_response)
    monkeypatch.setattr("app.routers.projects.query_osv_batch", mock_query)

    # 2. Create a project
    client.post(
        "/projects/",
        data={"name": "Project A"},
        files={"file": ("requirements.txt", b"requests==2.28.1", "text/plain")},
    )

    # 3. Get the dependency by name and version
    response = client.get("/dependencies/requests?version=2.28.1")
    assert response.status_code == 200
    details = response.json()
    assert len(details) == 1
    assert details[0]["name"] == "requests"
    assert details[0]["version"] == "2.28.1"
    assert details[0]["projects"] == ["Project A"]


def test_get_dependency_not_found():
    """
    Tests that GET /dependencies/{name} returns a 404 for a
    dependency that doesn't exist.
    """
    response = client.get("/dependencies/nonexistent-package")
    assert response.status_code == 404
    assert response.json()["detail"] == "Dependency 'nonexistent-package' not found."
