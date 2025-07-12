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
