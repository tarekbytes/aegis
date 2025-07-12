from pydantic import BaseModel
from typing import Optional, List

# Define Pydantic models for the responses
class ProjectResponse(BaseModel):
    project_id: int
    name: str
    description: Optional[str] = None
    dependencies: List[str]

class ProjectSummary(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
