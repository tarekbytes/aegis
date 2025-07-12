from typing import List
from fastapi import APIRouter

from app.data import store
from app.models.dependency import Dependency


router: APIRouter = APIRouter()


@router.get("/", response_model=List[Dependency])
async def get_all_dependencies():
    """
    Returns a list of all dependencies across all projects.
    """
    dependencies_data = store.get_all_dependencies()
    return [Dependency(**d) for d in dependencies_data] 