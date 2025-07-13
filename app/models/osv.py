from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class Query(BaseModel):
    commit: str | None = None
    package: dict | None = None


class Severity(BaseModel):
    type: str
    score: str

class AffectedPackage(BaseModel):
    package: Dict[str, Any]
    severity: Optional[List[Severity]] = None
    ranges: Optional[List[Dict[str, Any]]] = None
    versions: Optional[List[str]] = None
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None

class OSVVulnerability(BaseModel):
    id: str
    modified: Optional[str] = None
    published: Optional[str] = None
    withdrawn: Optional[str] = None
    aliases: Optional[List[str]] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[List[Severity]] = None
    affected: Optional[List[AffectedPackage]] = None
    references: Optional[List[Dict[str, Any]]] = None
    database_specific: Optional[Dict[str, Any]] = None

class QueryVulnerabilities(BaseModel):
    vulns: List[OSVVulnerability] = Field(default_factory=list)

class OSVBatchResponse(BaseModel):
    results: List[QueryVulnerabilities]
