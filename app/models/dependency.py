from typing import List
from pydantic import BaseModel


class Dependency(BaseModel):
    name: str
    version: str
    is_vulnerable: bool
    vulnerability_ids: List[str] = []
