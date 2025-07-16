from fastapi import APIRouter, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse
from starlette.status import (
    HTTP_201_CREATED,
    HTTP_404_NOT_FOUND,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_502_BAD_GATEWAY,
)
from typing import List, Optional, Tuple, Dict
from packaging.requirements import Requirement, InvalidRequirement
import httpx

from app.data import store
from app.models.project import ProjectResponse, ProjectSummary
from app.models.dependency import Dependency
from app.models.error import Error
from app.modules.osv import query_osv_batch


router: APIRouter = APIRouter()


async def get_validated_requirements(
    file: UploadFile = File(..., description="A requirements.txt file"),
) -> Tuple[List[Requirement], List[str]]:
    """
    Validates an uploaded requirements.txt file and returns the requirements
    and any validation errors.
    """
    contents = await file.read()
    requirements: List[Requirement] = []
    validation_errors: List[str] = []

    for i, line in enumerate(contents.decode().splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            req = Requirement(line)
            specifiers = list(req.specifier)
            if len(specifiers) != 1 or specifiers[0].operator != "==":
                validation_errors.append(f"Line {i+1}: '{line}' must be pinned with '=='.")
                continue
            requirements.append(req)
        except InvalidRequirement:
            validation_errors.append(f"Line {i+1}: '{line}' is not a valid requirement.")

    return requirements, validation_errors


@router.post("/", status_code=HTTP_201_CREATED, response_model=ProjectResponse)
async def create_project(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    validated_reqs: Tuple[List[Requirement], List[str]] = Depends(
        get_validated_requirements
    ),
):
    """
    Creates a new project and fetches vulnerability information for its
    dependencies.
    """
    requirements, validation_errors = validated_reqs
    if validation_errors:
        error = Error(
            name="ValidationError", description=", ".join(validation_errors)
        )
        return JSONResponse(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY, content=error.model_dump()
        )

    try:
        osv_response = await query_osv_batch(requirements)
        project_id = store.add_project(name=name, description=description)

        dependencies_to_store: List[Dict] = []
        for req, result in zip(requirements, osv_response.results):
            vulns = result.vulns if result and result.vulns else []
            dependencies_to_store.append(
                {
                    "name": req.name.lower(),
                    "version": str(next(iter(req.specifier)).version),
                    "is_vulnerable": bool(vulns),
                    "vulnerability_ids": [v.id for v in vulns],
                }
            )

        store.add_dependencies(project_id, dependencies_to_store)
        is_vulnerable = any(d["is_vulnerable"] for d in dependencies_to_store)

        return ProjectResponse(
            name=name,
            description=description,
            is_vulnerable=is_vulnerable,
        )
    except httpx.HTTPStatusError as e:
        error = Error(name="OSVServiceError", description=f"Error from OSV API: {e.response.text}")
        return JSONResponse(status_code=HTTP_502_BAD_GATEWAY, content=error.model_dump())


@router.get("/", response_model=list[ProjectSummary])
async def get_projects() -> list[ProjectSummary]:
    """
    Returns a summary of all projects.
    """
    projects_data = store.get_all_projects()
    summaries = []
    for p in projects_data:
        deps = store.get_dependencies_by_project_id(p["id"])
        is_vulnerable = any(d["is_vulnerable"] for d in deps if d["is_vulnerable"] is not None)
        summaries.append(ProjectSummary(**p, is_vulnerable=is_vulnerable))
    return summaries


@router.get("/{project_id}/dependencies", response_model=List[Dependency])
async def get_project_dependencies(project_id: int):
    """
    Returns the dependencies for a specific project.
    """
    dependencies_data = store.get_dependencies_by_project_id(project_id)
    if not dependencies_data:
        # Check if the project exists at all to return a 404
        projects = store.get_all_projects()
        if not any(p["id"] == project_id for p in projects):
            error = Error(name="ProjectNotFoundError", description=f"Project with ID {project_id} not found")
            return JSONResponse(status_code=HTTP_404_NOT_FOUND, content=error.model_dump())
    return [Dependency(**d) for d in dependencies_data]
