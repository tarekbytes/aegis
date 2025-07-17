import logging
from typing import List
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR

from app.data import store
from app.models.dependency import Dependency, DependencyDetail
from app.services.dependency_extractor import extract_all_dependencies


router: APIRouter = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/", response_model=List[Dependency])
async def get_all_dependencies():
    """
    Returns a list of all dependencies across all projects.
    """
    dependencies_data = store.get_all_dependencies()
    return [Dependency(**d) for d in dependencies_data]


@router.get("/{name}", response_model=List[DependencyDetail])
async def get_dependency(name: str, version: str | None = None):
    """
    Returns a list of all dependencies that have the same name.
    If version is specified, it will return information about the exact dependency version.
    """
    dependency_details = store.get_dependency_details(name.lower(), version)
    if not dependency_details:
        logger.error(f"Dependency '{name}' not found.")
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail=f"Dependency '{name}' not found.",
        )
    return [DependencyDetail(**d) for d in dependency_details]


@router.post("/extract-dependencies", response_class=PlainTextResponse)
async def extract_dependencies_endpoint(file: UploadFile = File(...)):
    """
    Accepts a requirements.txt file and returns a new requirements.txt content with all dependencies (direct + transitive) explicitly listed.
    """
    try:
        contents = await file.read()
        expanded = await extract_all_dependencies(contents.decode())
        return expanded
    except Exception as e:
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dependency extraction failed: {str(e)}"
        )
