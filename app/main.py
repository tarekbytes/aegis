import logging
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from app.routers import projects, dependencies
from app.services import scheduler
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app):
    logger.info("Starting scheduler...")
    scheduler.start()
    try:
        yield
    finally:
        logger.info("Shutting down scheduler...")
        scheduler.shutdown()

app = FastAPI(lifespan=lifespan)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception in {request.method} {request.url.path}")
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "exception_type": exc.__class__.__name__,
            "exception_message": str(exc)
        }
    )

@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "You seem lost!"}

app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(
    dependencies.router, prefix="/dependencies", tags=["dependencies"]
)
