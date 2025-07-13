from pydantic import BaseModel
from typing import Optional


class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None


class Project(ProjectBase):
    id: int


class ProjectCreate(ProjectBase):
    pass


# Define Pydantic models for the responses
class ProjectResponse(ProjectBase):
    is_vulnerable: bool


class ProjectSummary(Project):
    is_vulnerable: bool
