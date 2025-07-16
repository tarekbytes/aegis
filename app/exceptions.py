class ConflictError(Exception):
    """Base exception for data conflicts."""

    pass


class DuplicateProjectError(ConflictError):
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Project with name '{name}' already exists.")
