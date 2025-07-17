from datetime import datetime
from typing import List
from pydantic import BaseModel, Field



class Dependency(BaseModel):
    name: str
    version: str
    is_vulnerable: bool
    vulnerability_ids: List[str] = []


class DependencyDetail(Dependency):
    projects: List[str] = Field(
        ...,
        title="Projects",
        description="List of project names using this dependency.",
    )
    queried_at: datetime
