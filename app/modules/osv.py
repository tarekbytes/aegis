import httpx
from typing import List, Dict, Any
import time
from packaging.requirements import Requirement
from app.models import OSVBatchResponse, OSVVulnerability, QueryVulnerabilities
from app.services.cache import cache, CacheEntry

OSV_API_URL = "https://api.osv.dev/v1/querybatch"

# TTLs in seconds
TTL_NONE = 86400      # 24h for no vulns or LOW
TTL_MODERATE = 43200  # 12h
TTL_HIGH = 14400      # 4h
TTL_CRITICAL = 3600   # 1h
TTL_DEFAULT = 3600    # 1h fallback

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW"]
SEVERITY_TTL = {
    "CRITICAL": TTL_CRITICAL,
    "HIGH": TTL_HIGH,
    "MODERATE": TTL_MODERATE,
    "LOW": TTL_NONE,
}

def _extract_highest_severity(vulns: List[OSVVulnerability]) -> str:
    highest = None
    for vuln in vulns:
        # Check top-level severity
        if vuln.severity:
            for sev in vuln.severity:
                sev_type = sev.type.upper()
                if highest is None or SEVERITY_ORDER.index(sev_type) < SEVERITY_ORDER.index(highest):
                    highest = sev_type
        # Check affected-level severity
        if vuln.affected:
            for aff in vuln.affected:
                if aff.severity:
                    for sev in aff.severity:
                        sev_type = sev.type.upper()
                        if highest is None or SEVERITY_ORDER.index(sev_type) < SEVERITY_ORDER.index(highest):
                            highest = sev_type
    return highest or "LOW"

def _calculate_ttl(vulns: List[OSVVulnerability]) -> int:
    if not vulns:
        return TTL_NONE
    highest = _extract_highest_severity(vulns)
    return SEVERITY_TTL.get(highest, TTL_DEFAULT)

async def query_osv_batch(requirements: List[Requirement]) -> OSVBatchResponse:
    dep_keys = []
    dep_map = {}
    for req in requirements:
        version = str(next(iter(req.specifier)).version)
        key = f"{req.name.lower()}@{version}"
        dep_keys.append(key)
        dep_map[key] = req

    results: Dict[str, Any] = {}
    to_fetch = []
    waiters = []
    now = time.time()

    # Phase 1: Check cache and lock misses
    for key in dep_keys:
        entry = await cache.get(key)
        if entry is None:
            added = await cache.add_if_not_exists(key, CacheEntry(status='fetching'))
            if added:
                to_fetch.append(key)
            else:
                waiters.append(key)
        elif entry.status == 'ready':
            if entry.expiry_timestamp and entry.expiry_timestamp > now:
                results[key] = entry.data
            else:
                results[key] = entry.data
                added = await cache.add_if_not_exists(key + ':refresh', CacheEntry(status='fetching'))
                if added:
                    to_fetch.append(key)
        elif entry.status == 'fetching':
            waiters.append(key)

    # Phase 2: Fetch from OSV for to_fetch
    if to_fetch:
        queries = []
        fetch_keys = []
        for key in to_fetch:
            req = dep_map[key]
            version = str(next(iter(req.specifier)).version)
            queries.append({"package": {"purl": f"pkg:pypi/{req.name}@{version}"}})
            fetch_keys.append(key)
        async with httpx.AsyncClient() as client:
            response = await client.post(OSV_API_URL, json={"queries": queries})
            response.raise_for_status()
            batch = OSVBatchResponse.model_validate(response.json())
        for key, res in zip(fetch_keys, batch.results):
            vulns = res.vulns or []
            ttl = _calculate_ttl(vulns)
            expiry = time.time() + ttl
            await cache.set(key, CacheEntry(status='ready', data=res, expiry_timestamp=expiry))
            # Clear the refresh entry
            await cache._lock.acquire()
            try:
                cache._store.pop(key + ':refresh', None)
            finally:
                cache._lock.release()
            results[key] = res

    # Phase 3: Wait for in-flight fetches
    for key in waiters:
        data = await cache.wait_for_ready(key)
        if data is not None:
            results[key] = data
        else:
            results[key] = QueryVulnerabilities(vulns=[])

    return OSVBatchResponse(results=[results[k] for k in dep_keys])
