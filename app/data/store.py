from datetime import datetime, timezone
from typing import Dict, List, Optional


_projects: List[Dict] = []
_dependencies: List[Dict] = []
_next_project_id: int = 1
_next_dependency_id: int = 1


def get_all_projects() -> List[Dict]:
    """Returns all projects from the in-memory store."""
    return _projects


def add_project(name: str, description: Optional[str]) -> int:
    """Adds a new project to the in-memory store and returns its ID."""
    global _next_project_id
    project_data = {
        "id": _next_project_id,
        "name": name,
        "description": description,
    }
    _projects.append(project_data)
    project_id = _next_project_id
    _next_project_id += 1
    return project_id


def add_dependencies(project_id: int, dependencies: List[Dict]):
    """Adds a batch of dependencies for a project to the in-memory store."""
    global _next_dependency_id
    for dep in dependencies:
        dep_data = {
            "id": _next_dependency_id,
            "project_id": project_id,
            "name": dep["name"],
            "version": dep["version"],
            "is_vulnerable": dep["is_vulnerable"],
            "vulnerability_ids": dep["vulnerability_ids"],
            "queried_at": datetime.now(timezone.utc),
        }
        _dependencies.append(dep_data)
        _next_dependency_id += 1


def get_dependencies_by_project_id(project_id: int) -> List[Dict]:
    """Returns all dependencies for a given project_id."""
    return [dep for dep in _dependencies if dep["project_id"] == project_id]


def get_all_dependencies() -> List[Dict]:
    """Returns all dependencies from the in-memory store."""
    return _dependencies


def get_dependency_details(name: str, version: Optional[str] = None) -> List[Dict]:
    """
    Returns details for a dependency, including all projects that use it.
    If version is specified, it returns details for that specific version.
    """
    if version:
        deps = [d for d in _dependencies if d["name"] == name and d["version"] == version]
    else:
        deps = [d for d in _dependencies if d["name"] == name]

    if not deps:
        return []

    # Although we might have multiple dependency records for the same name/version
    # (one for each project that uses it), the core details will be the same.
    # We can take the details from the first record we found.
    first_dep = deps[0]

    # Find all projects that use this dependency (any version if not specified)
    project_ids = {d["project_id"] for d in deps}
    projects_using_dep = list(
        {p["name"] for p in _projects if p["id"] in project_ids}
    )

    details = {
        "name": first_dep["name"],
        "version": first_dep["version"],
        "is_vulnerable": first_dep["is_vulnerable"],
        "vulnerability_ids": first_dep["vulnerability_ids"],
        "projects": projects_using_dep,
        "queried_at": first_dep["queried_at"],
    }
    
    # If no version is specified, we should return a list of details for each version
    if not version:
        # Group dependencies by version
        deps_by_version: Dict[str, List[Dict]] = {}
        for d in deps:
            deps_by_version.setdefault(d["version"], []).append(d)

        results = []
        for ver, version_deps in deps_by_version.items():
            first_ver_dep = version_deps[0]
            project_ids = {d["project_id"] for d in version_deps}
            projects_using_dep = list(
                {p["name"] for p in _projects if p["id"] in project_ids}
            )
            results.append({
                "name": first_ver_dep["name"],
                "version": ver,
                "is_vulnerable": first_ver_dep["is_vulnerable"],
                "vulnerability_ids": first_ver_dep["vulnerability_ids"],
                "projects": projects_using_dep,
                "queried_at": first_ver_dep["queried_at"],
            })
        return results

    return [details]


def clear_projects_store():
    """Clears all projects from the store (for testing)."""
    global _next_project_id
    _projects.clear()
    _next_project_id = 1


def clear_dependencies_store():
    """Clears all dependencies from the store (for testing)."""
    global _next_dependency_id
    _dependencies.clear()
    _next_dependency_id = 1 
