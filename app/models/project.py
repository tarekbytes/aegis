from pydantic import BaseModel

# Define Pydantic models for the responses
class ProjectResponse(BaseModel):
    name: str
    description: str
    requirements: str

class ProjectSummary(BaseModel):
    id: int
    name: str
    description: str
