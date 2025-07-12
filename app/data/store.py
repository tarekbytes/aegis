from typing import Dict, List, Optional


_projects: List[Dict] = []
_next_project_id: int = 1


def get_all_projects() -> List[Dict]:
    """Returns all projects from the in-memory store."""
    return _projects


def add_project(name: str, description: Optional[str]) -> Dict:
    """Adds a new project to the in-memory store."""
    global _next_project_id
    project_data = {
        "id": _next_project_id,
        "name": name,
        "description": description,
    }
    _projects.append(project_data)
    _next_project_id += 1
    return project_data


def clear_projects_store():
    """Clears all projects from the store (for testing)."""
    global _next_project_id
    _projects.clear()
    _next_project_id = 1 
