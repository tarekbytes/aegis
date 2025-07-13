import httpx
from typing import List

from packaging.requirements import Requirement

from app.models import OSVBatchResponse


OSV_API_URL = "https://api.osv.dev/v1/querybatch"


async def query_osv_batch(requirements: List[Requirement]) -> OSVBatchResponse:
    """
    Queries the OSV API with a batch of requirements using package URLs (purls).

    NOTE: This function assumes all requirements have been validated to have
    exactly one pinned version specifier (e.g., '==1.2.3').

    Returns:
        An OSVBatchResponse object containing the parsed vulnerability data.
    """
    queries = []
    for req in requirements:
        version = str(next(iter(req.specifier)).version)
        queries.append({"package": {"purl": f"pkg:pypi/{req.name}@{version}"}})

    if not queries:
        return OSVBatchResponse(results=[])

    async with httpx.AsyncClient() as client:
        response = await client.post(OSV_API_URL, json={"queries": queries})
        response.raise_for_status()
        return OSVBatchResponse.parse_obj(response.json())
