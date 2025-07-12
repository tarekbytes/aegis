from fastapi import APIRouter, Depends, File, Form, UploadFile
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_502_BAD_GATEWAY,
)
from starlette.exceptions import HTTPException
from packaging.requirements import Requirement, InvalidRequirement
import httpx
from typing import List, Optional

from app.data import store
from app.models.project import ProjectResponse, ProjectSummary
from app.services.osv import query_osv_batch


router: APIRouter = APIRouter()


async def validate_requirements_file(
    file: UploadFile = File(..., description="A requirements.txt file")
) -> List[Requirement]:
    """
    Dependency that validates an uploaded requirements.txt file and returns a list of requirements.
    """
    file.file.seek(0)
    content: str = file.file.read().decode("utf-8")

    requirements: list[Requirement] = []
    invalid_lines: list[str] = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        try:
            requirements.append(Requirement(line))
        except InvalidRequirement as e:
            invalid_lines.append(f"Line {i}: {e}")

    if invalid_lines:
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Invalid lines found in the requirements file.",
                "errors": invalid_lines
            },
        )

    return requirements


@router.post("/", status_code=HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    requirements: List[Requirement] = Depends(validate_requirements_file),
) -> ProjectResponse:
    """
    Creates a new project and returns vulnerability information for its dependencies.
    - **name**: The name of the project.
    - **description**: An optional description for the project.
    - **file**: The `requirements.txt` file for the project.
    """
    try:
        osv_response = await query_osv_batch(requirements)
        is_vulnerable = any(query.vulns for query in osv_response.results)
        store.add_project(name=name, description=description)
        return ProjectResponse(
            name=name, description=description, is_vulnerable=is_vulnerable
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=HTTP_502_BAD_GATEWAY,
            detail=f"Error from OSV API: {e.response.text}",
        )


@router.get("/", response_model=list[ProjectSummary])
async def get_projects() -> list[ProjectSummary]:
    projects_data = store.get_all_projects()
    return [ProjectSummary(**p) for p in projects_data]
