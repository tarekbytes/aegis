from pydantic import BaseModel, Field
from typing import List


class Query(BaseModel):
    commit: str | None = None
    package: dict | None = None


class OSVAbbreviatedVulnerability(BaseModel):
    id: str
    modified: str

class QueryVulnerabilities(BaseModel):
    vulns: List[OSVAbbreviatedVulnerability] = Field(default_factory=list)

class OSVBatchResponse(BaseModel):
    results: List[QueryVulnerabilities]
