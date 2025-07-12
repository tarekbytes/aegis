from fastapi import FastAPI

from app.routers import projects

app: FastAPI = FastAPI()


@app.get("/")
async def read_root() -> dict[str, str]:
    return {"message": "You seem lost!"}


app.include_router(projects.router, prefix="/projects", tags=["projects"])
