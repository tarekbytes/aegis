from fastapi import APIRouter, File, UploadFile, Form, Depends, HTTPException, status
import io
from packaging.requirements import Requirement, InvalidRequirement
from app.models.project import ProjectResponse, ProjectSummary

router: APIRouter = APIRouter()


async def validate_requirements_file(file: UploadFile = File(..., description="A requirements.txt file")) -> UploadFile:
    """
    Dependency that validates an uploaded requirements.txt file.
    """
    file.file.seek(0)
    content: str = file.file.read().decode("utf-8")

    invalid_lines: list[str] = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        try:
            Requirement(line)
        except InvalidRequirement as e:
            invalid_lines.append(f"Line {i}: {e}")

    if invalid_lines:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Invalid lines found in the requirements file.",
                "errors": invalid_lines
            },
        )

    file.file.seek(0)
    return file


@router.post(
    "/",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        422: {"description": "Validation Error: Invalid lines in requirements file"}
    }
)
async def create_project(
    name: str = Form(...),
    description: str = Form(...),
    requirements: UploadFile = Depends(validate_requirements_file)
) -> ProjectResponse:
    """
    Creates a new project. The uploaded 'requirements' file is validated
    by the dependency before this endpoint code is run.
    """
    requirements_content: bytes = await requirements.read()

    # TODO: Implement the logic to save the project and process the requirements ...

    return ProjectResponse(
        name=name,
        description=description,
        requirements=requirements.filename,
    )


@router.get("/", response_model=list[ProjectSummary])
async def get_projects() -> list[ProjectSummary]:
    # Until the create project endpoint is implemented, we'll return dummy data.
    dummy_projects = [
        ProjectSummary(id=1, name="Project Alpha", description="This is a dummy project"),
        ProjectSummary(id=2, name="Project Beta", description="This is another dummy project"),
    ]
    return dummy_projects
