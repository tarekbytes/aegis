import logging
from typing import List
from fastapi import APIRouter, HTTPException
from starlette.status import HTTP_404_NOT_FOUND

from app.data import store
from app.models.dependency import Dependency, DependencyDetail


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
