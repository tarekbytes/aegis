from pydantic import BaseModel
from typing import Optional, List

# Define Pydantic models for the responses
class ProjectResponse(BaseModel):
    name: str
    description: Optional[str]
    is_vulnerable: bool

class ProjectSummary(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    is_vulnerable: bool
