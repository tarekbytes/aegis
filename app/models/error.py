from pydantic import BaseModel


class Error(BaseModel):
    name: str
    description: str
