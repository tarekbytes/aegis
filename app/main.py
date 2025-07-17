from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from starlette.status import HTTP_409_CONFLICT

from app.exceptions import ConflictError
from app.models.error import Error
from app.routers import projects, dependencies
from app.services import scheduler
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    print("Starting scheduler...")
    scheduler.start()
    try:
        yield
    finally:
        print("Shutting down scheduler...")
        scheduler.shutdown()

app = FastAPI(lifespan=lifespan)

@app.exception_handler(ConflictError)
async def conflict_exception_handler(request: Request, exc: ConflictError):
    error = Error(name=type(exc).__name__, description=str(exc))
    return JSONResponse(status_code=HTTP_409_CONFLICT, content=error.model_dump())

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    error = Error(name=type(exc).__name__, description=str(exc))
    return JSONResponse(status_code=500, content=error.model_dump())

@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "You seem lost!"}


app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(
    dependencies.router, prefix="/dependencies", tags=["dependencies"]
)
