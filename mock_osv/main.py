from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI()

class Severity(BaseModel):
    type: str
    score: str

class AffectedPackage(BaseModel):
    package: Dict[str, Any]
    severity: List[Severity] = []
    ranges: List[Dict[str, Any]] = []
    versions: List[str] = []
    ecosystem_specific: Dict[str, Any] = {}
    database_specific: Dict[str, Any] = {}

class OSVVulnerability(BaseModel):
    id: str
    severity: List[Severity] = []
    affected: List[AffectedPackage] = []
    # Add more fields as needed for your tests

class QueryVulnerabilities(BaseModel):
    vulns: List[OSVVulnerability] = []

class OSVBatchResponse(BaseModel):
    results: List[QueryVulnerabilities]

@app.post("/v1/querybatch")
async def querybatch(request: Request):
    body = await request.json()
    queries = body.get("queries", [])
    results = []
    for q in queries:
        purl = q.get("package", {}).get("purl", "")
        vuln = OSVVulnerability(
            id="MOCK-CRITICAL-0001",
            severity=[Severity(type="CRITICAL", score="10.0")],
            affected=[AffectedPackage(package={"purl": purl})]
        )
        results.append({"vulns": [vuln.dict()]})
    return {"results": results}
