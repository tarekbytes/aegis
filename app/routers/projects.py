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
from app.models.dependency import Dependency
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
        if not line or line.startswith("#"):
            continue
        try:
            requirements.append(Requirement(line))
        except InvalidRequirement:
            invalid_lines.append(f"Line {i}: {line}")

    if invalid_lines:
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"errors": invalid_lines},
        )

    return requirements


@router.post("/", status_code=HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    requirements: List[Requirement] = Depends(validate_requirements_file),
):
    """
    Creates a new project, queries OSV for vulnerabilities, and stores the results.
    - **name**: The name of the project.
    - **description**: An optional description for the project.
    - **file**: The `requirements.txt` file for the project.
    """
    try:
        osv_response = await query_osv_batch(requirements)
        project_id = store.add_project(name=name, description=description)

        dependencies_to_store = []
        for req, result in zip(requirements, osv_response.results):
            vulns = result.vulns
            dependencies_to_store.append(
                {
                    "name": req.name,
                    "version": str(next(iter(req.specifier)).version),
                    "is_vulnerable": bool(vulns),
                    "vulnerability_ids": [v.id for v in vulns],
                }
            )
        store.add_dependencies(project_id, dependencies_to_store)

        is_vulnerable = any(d["is_vulnerable"] for d in dependencies_to_store)

        return ProjectResponse(
            name=name, description=description, is_vulnerable=is_vulnerable
        )
    except httpx.HTTPStatusError as e:
        # This indicates a server-side error from the OSV API
        raise HTTPException(
            status_code=HTTP_502_BAD_GATEWAY,
            detail=f"Error from OSV API: {e.response.text}",
        )


@router.get("/", response_model=list[ProjectSummary])
async def get_projects() -> list[ProjectSummary]:
    """
    Returns a summary of all projects.
    """
    projects_data = store.get_all_projects()
    return [ProjectSummary(**p) for p in projects_data]


@router.get("/{project_id}/dependencies", response_model=List[Dependency])
async def get_project_dependencies(project_id: int):
    """
    Returns the dependencies for a specific project.
    """
    dependencies_data = store.get_dependencies_by_project_id(project_id)
    return [Dependency(**d) for d in dependencies_data]
