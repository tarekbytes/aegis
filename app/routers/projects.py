from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
import io
from typing import List, Optional
from packaging.requirements import Requirement, InvalidRequirement
from app.models.project import ProjectResponse, ProjectSummary

router: APIRouter = APIRouter()


async def validate_requirements_file(
    file: UploadFile = File(...),
) -> List[Requirement]:
    """
    Reads an uploaded requirements.txt file, validates its syntax,
    and returns a list of Requirement objects.

    Raises:
        HTTPException: If the file contains invalid syntax.
    """
    contents: str = (await file.read()).decode("utf-8")
    parsed_requirements: List[Requirement] = []
    for i, line in enumerate(contents.splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed_requirements.append(Requirement(line))
        except InvalidRequirement:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid requirement on line {i + 1}: {line}",
            )
    return parsed_requirements


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    requirements: List[Requirement] = Depends(validate_requirements_file),
) -> ProjectResponse:
    """
    Creates a new project.
    - **name**: The name of the project.
    - **description**: An optional description for the project.
    - **file**: The `requirements.txt` file for the project.
    """
    # For now, we'll just return the parsed data.
    # In the future, this will involve database operations.
    dependency_strings: List[str] = [str(req) for req in requirements]
    return ProjectResponse(
        project_id=1,  # Dummy ID
        name=name,
        description=description,
        dependencies=dependency_strings,
    )


@router.get("/", response_model=list[ProjectSummary])
async def get_projects() -> list[ProjectSummary]:
    # Until the create project endpoint is implemented, we'll return dummy data.
    dummy_projects = [
        ProjectSummary(id=1, name="Project Alpha", description="This is a dummy project"),
        ProjectSummary(id=2, name="Project Beta", description="This is another dummy project"),
    ]
    return dummy_projects
