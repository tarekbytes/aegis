class ConflictError(Exception):
    """Base exception for data conflicts."""

    pass


class DuplicateProjectError(ConflictError):
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Project with name '{name}' already exists.")


class ProjectNotFoundError(Exception):
    """Raised when a project with the given ID is not found."""
    def __init__(self, project_id):
        super().__init__(f"Project with id {project_id} not found")
        self.project_id = project_id
