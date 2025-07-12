from fastapi import FastAPI

from app.routers import projects, dependencies

app: FastAPI = FastAPI()


@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "You seem lost!"}


app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(
    dependencies.router, prefix="/dependencies", tags=["dependencies"]
)
