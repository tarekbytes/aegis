from unittest.mock import AsyncMock
from starlette.status import HTTP_200_OK, HTTP_404_NOT_FOUND

from fastapi.testclient import TestClient

from app.main import app
from app.models import OSVVulnerability, QueryVulnerabilities, OSVBatchResponse
from app.models.osv import AffectedPackage, Severity


client = TestClient(app)


def make_vuln(severity_type=None):
    sev = [Severity(type=severity_type, score="7.5")] if severity_type else None
    return OSVVulnerability(
        id="VULN-2",
        severity=sev,
        affected=[AffectedPackage(package={"ecosystem": "PyPI", "name": "bar"}, severity=sev)]
    )

def test_osv_vuln_affect():
    v = make_vuln("MODERATE")
    # Use attribute access for Pydantic models
    assert v.affected is not None
    assert v.affected[0].package["name"] == "bar"
    assert v.affected[0].severity is not None
    assert v.affected[0].severity[0].type == "MODERATE"

def test_query_vulnerabilities():
    vulns = [make_vuln("LOW"), make_vuln("HIGH")]
    qv = QueryVulnerabilities(vulns=vulns)
    assert qv.vulns[0].severity is not None
    assert qv.vulns[1].severity is not None
    assert qv.vulns[0].severity[0].type == "LOW"
    assert qv.vulns[1].severity[0].type == "HIGH"


def test_get_all_dependencies(monkeypatch):
    """
    Tests that the global GET /dependencies endpoint returns a flat list of
    all dependencies from multiple projects.
    """
    # Mock the dependency extractor
    mock_extractor = AsyncMock(side_effect=["requests==2.28.1\n", "bar==1.0.0\n"])
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # 1. Mock the OSV response for two separate project creations
    mock_osv_response_1 = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_osv_response_2 = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[make_vuln("MODERATE")])])
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
        files={"file": ("requirements.txt", b"bar==1.0.0", "text/plain")},
    )
    # 4. Get all dependencies
    response = client.get("/dependencies")
    assert response.status_code == HTTP_200_OK
    assert isinstance(response.json(), list)


def test_get_dependency_by_name(monkeypatch):
    """
    Tests that GET /dependencies/{name} returns all versions of a dependency
    if it exists in multiple projects.
    """
    # Mock the dependency extractor
    mock_extractor = AsyncMock(side_effect=["requests==2.28.1\n", "requests==2.28.2\n"])
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
    # 1. Mock OSV responses
    mock_osv_response_1 = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
    mock_osv_response_2 = OSVBatchResponse(results=[QueryVulnerabilities(vulns=[])])
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
    # 3. Get dependency by name
    response = client.get("/dependencies/requests")
    assert response.status_code == HTTP_200_OK
    assert isinstance(response.json(), list)


def test_get_dependency_by_name_and_version(monkeypatch):
    """
    Tests that GET /dependencies/{name}?version={version} returns the
    correct specific version of a dependency.
    """
    # Mock the dependency extractor
    mock_extractor = AsyncMock(return_value="requests==2.28.1\n")
    monkeypatch.setattr("app.routers.projects.extract_all_dependencies", mock_extractor)
    
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
    # 3. Get dependency by name and version
    response = client.get("/dependencies/requests?version=2.28.1")
    assert response.status_code == HTTP_200_OK
    assert isinstance(response.json(), list)


def test_get_dependency_not_found():
    """
    Tests that GET /dependencies/{name} returns a 404 for a
    dependency that doesn't exist.
    """
    response = client.get("/dependencies/nonexistent-package")
    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Dependency 'nonexistent-package' not found."
