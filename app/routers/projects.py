from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import JSONResponse
from starlette.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_404_NOT_FOUND,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_502_BAD_GATEWAY,
    HTTP_409_CONFLICT,
)
from typing import List, Optional, Tuple, Dict
from packaging.requirements import Requirement, InvalidRequirement
import httpx
import logging

from app.data import store
from app.models.project import ProjectResponse, ProjectSummary
from app.models.dependency import Dependency
from app.modules.osv import query_osv_batch
from app.exceptions import DuplicateProjectError, ProjectNotFoundError
from app.services.dependency_extractor import extract_all_dependencies


router: APIRouter = APIRouter()


async def get_validated_requirements(
    file: UploadFile = File(..., description="A requirements.txt file"),
) -> Tuple[List[Requirement], List[str]]:
    """
    Validates an uploaded requirements.txt file and returns the requirements
    and any validation errors. Uses dependency extractor to expand requirements first.
    """
    contents = await file.read()
    original_content = contents.decode()
    requirements: List[Requirement] = []
    validation_errors: List[str] = []

    try:
        # First, expand dependencies using the extractor
        await extract_all_dependencies(original_content)
        
        # Validate the original requirements first to get proper line numbers
        original_lines = original_content.splitlines()
        for i, line in enumerate(original_lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Comprehensive filtering for pip requirement syntax
            # Handle all forms: -r file.txt, -rfile.txt, --requirement file.txt, --requirement=file.txt
            if (line.startswith("-r ") or line.startswith("-r") or 
                line.startswith("--requirement ") or line.startswith("--requirement=") or
                line.startswith("-f ") or line.startswith("-f") or
                line.startswith("--find-links ") or line.startswith("--find-links=") or
                line.startswith("--index-url ") or line.startswith("--index-url=") or
                line.startswith("--extra-index-url ") or line.startswith("--extra-index-url=") or
                line.startswith("--trusted-host ") or line.startswith("--trusted-host=") or
                line.startswith("--no-index") or line.startswith("--no-deps") or
                line.startswith("--pre") or line.startswith("--editable") or
                line.startswith("-e ") or line.startswith("-e")):
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
                
    except Exception as e:
        validation_errors.append(f"Failed to extract dependencies: {str(e)}")

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
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY, 
            detail=", ".join(validation_errors)
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
    except DuplicateProjectError as e:
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=HTTP_502_BAD_GATEWAY,
            detail=f"Error from OSV API: {e.response.text}"
        )
    except Exception as e:
        logging.getLogger(__name__).exception(f"Unexpected error in create_project: {e}")
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.put("/{project_id}", status_code=HTTP_200_OK, response_model=ProjectResponse)
async def update_project(
    project_id: int,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    validated_reqs: Tuple[List[Requirement], List[str]] = Depends(
        get_validated_requirements
    ),
):
    """
    Updates a project and fetches vulnerability information for its
    dependencies.
    """
    requirements, validation_errors = validated_reqs
    if validation_errors:
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY, 
            detail=", ".join(validation_errors)
        )

    try:
        osv_response = await query_osv_batch(requirements)
        store.update_project(project_id, name=name, description=description)

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

        store.update_dependencies(project_id, dependencies_to_store)
        is_vulnerable = any(d["is_vulnerable"] for d in dependencies_to_store)

        return ProjectResponse(
            name=name,
            description=description,
            is_vulnerable=is_vulnerable,
        )
    except DuplicateProjectError as e:
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail=str(e))
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=HTTP_502_BAD_GATEWAY,
            detail=f"Error from OSV API: {e.response.text}"
        )
    except Exception as e:
        logging.getLogger(__name__).exception(f"Unexpected error in update_project: {e}")
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



@router.delete("/{project_id}", status_code=HTTP_200_OK)
async def delete_project(project_id: int):
    """
    Deletes a project.
    """
    try:
        store.delete_project(project_id)
        return JSONResponse(status_code=HTTP_200_OK, content={"message": "Project deleted successfully"})
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logging.getLogger(__name__).exception(f"Unexpected error in delete_project: {e}")
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    
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
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND,
                detail=f"Project with ID {project_id} not found"
            )
    return [Dependency(**d) for d in dependencies_data]
