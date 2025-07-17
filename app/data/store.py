from datetime import datetime, timezone
from typing import Dict, List, Optional
import logging

from app.exceptions import DuplicateProjectError, ProjectNotFoundError

logger = logging.getLogger(__name__)

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

    """When we switch to posgres, this will be a check for a unique constraint on the name column."""
    if any(project["name"] == name for project in _projects):
        logger.error(f"Error creating project -- project {name} already exists")
        raise DuplicateProjectError(name)

    project_data = {
        "id": _next_project_id,
        "name": name,
        "description": description,
    }
    _projects.append(project_data)
    project_id = _next_project_id
    _next_project_id += 1
    return project_id


def update_project(project_id: int, name: str, description: Optional[str]) -> int:
    """Updates a project in the in-memory store."""
    global _projects
    # fetch project by id
    project = next((p for p in _projects if p["id"] == project_id), None)
    if not project:
        logger.error(f"Error updating project -- project with id {project_id} not found")
        raise ProjectNotFoundError(project_id)

    """Check all the other projects to make sure the name is unique."""
    if any(project["name"] == name for project in _projects if project["id"] != project_id):
        logger.error(f"Error updating project -- project {name} already exists")
        raise DuplicateProjectError(name)

    project_data = {
        "id": project_id,
        "name": name,
        "description": description,
    }

    for p in _projects:
        if p["id"] == project_id:
            p.update(project_data)
            break
    
    return project_id


def delete_project(project_id: int) -> int:
    """Deletes a project in the in-memory store."""
    global _projects
    # fetch project by id
    project = next((p for p in _projects if p["id"] == project_id), None)
    if not project:
        logger.error(f"Error deleting project -- project with id {project_id} not found")
        raise ProjectNotFoundError(project_id)

    _projects = remove_project_by_id(project_id)
    
    # Also delete all dependencies associated with this project
    delete_dependencies_by_project_id(project_id)
    
    return project_id

def remove_project_by_id(target_id: int) -> List[Dict]:
    """
    Removes projects whose 'id' equals target_id.
    """
    return [p for p in _projects if p.get("id") != target_id]


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


def update_dependencies(project_id: int, dependencies: List[Dict]):
    """Updates dependencies for a project by first removing existing ones and then adding new ones."""
    # First, delete all existing dependencies for this project
    delete_dependencies_by_project_id(project_id)
    # Then add the new dependencies
    add_dependencies(project_id, dependencies)


def delete_dependencies_by_project_id(project_id: int):
    """Deletes all dependencies for a given project_id."""
    global _dependencies
    _dependencies = [dep for dep in _dependencies if dep["project_id"] != project_id]


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
    name = name.lower()
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


def update_dependency_vulnerability(name: str, version: str, is_vulnerable: bool, vulnerability_ids: list):
    """
    Updates the vulnerability status and IDs for all dependencies matching the given name and version.
    """
    name = name.lower()
    for dep in _dependencies:
        if dep["name"] == name and dep["version"] == version:
            dep["is_vulnerable"] = is_vulnerable
            dep["vulnerability_ids"] = vulnerability_ids
