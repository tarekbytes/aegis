import logging
import time
from typing import TYPE_CHECKING, List

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from packaging.requirements import Requirement
from pytz import utc

from app.data import store
from app.models.osv import OSVBatchResponse, OSVVulnerability
from app.modules.osv import (
    SEVERITY_ORDER,
    SEVERITY_TTL,
    TTL_CRITICAL,
    TTL_DEFAULT,
    TTL_NONE,
    query_osv_batch,
)
from app.services.cache import CacheEntry, cache

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=utc)


def _extract_highest_severity(vulns: List[OSVVulnerability]) -> str:
    highest = None
    for vuln in vulns:
        # Check top-level severity
        if vuln.severity:
            for sev in vuln.severity:
                sev_type = sev.type.upper()
                if highest is None or SEVERITY_ORDER.index(
                    sev_type
                ) < SEVERITY_ORDER.index(highest):
                    highest = sev_type
        # Check affected-level severity
        if vuln.affected:
            for aff in vuln.affected:
                if aff.severity:
                    for sev in aff.severity:
                        sev_type = sev.type.upper()
                        if highest is None or SEVERITY_ORDER.index(
                            sev_type
                        ) < SEVERITY_ORDER.index(highest):
                            highest = sev_type
    return highest or "LOW"


def _calculate_ttl(vulns: List[OSVVulnerability]) -> int:
    if not vulns:
        return TTL_NONE
    highest = _extract_highest_severity(vulns)
    return SEVERITY_TTL.get(highest, TTL_DEFAULT)


async def scheduled_vulnerability_scan():
    """
    Periodically scans all unique dependencies in the store, checks for stale
    cache entries, and re-queries OSV for the latest vulnerability data.
    """
    # 1. Get all unique dependencies in use (name and version)
    all_deps = store.get_all_dependencies()
    unique_deps = {(dep["name"], dep["version"]) for dep in all_deps}

    # 2. Filter for stale cache entries
    stale_deps_reqs: list[Requirement] = []
    for name, version in unique_deps:
        cache_key = f"{name.lower()}@{version}"
        entry = await cache.get(cache_key)
        # Check if entry is missing or expired
        if not entry or (
            entry.expiry_timestamp and time.time() > entry.expiry_timestamp
        ):
            stale_deps_reqs.append(Requirement(f"{name}=={version}"))

    if not stale_deps_reqs:
        logger.info("No stale dependencies to scan.")
        return

    logger.info(f"Found {len(stale_deps_reqs)} stale dependencies to scan.")
    # 3. Batch query osv.dev for stale dependencies
    osv_results: OSVBatchResponse = await query_osv_batch(stale_deps_reqs)

    # 4. Update cache and store for each result
    for req, query_vulns in zip(stale_deps_reqs, osv_results.results):
        version = str(next(iter(req.specifier)).version)
        name = req.name.lower()
        cache_key = f"{name}@{version}"

        has_vulns = query_vulns.vulns is not None and len(query_vulns.vulns) > 0
        vuln_ids = [v.id for v in query_vulns.vulns] if has_vulns else []

        # Update cache with new data and expiry
        ttl = _calculate_ttl(query_vulns.vulns or [])
        new_entry = CacheEntry(
            status="ready", data=query_vulns, expiry_timestamp=time.time() + ttl
        )
        await cache.set(cache_key, new_entry)
        logger.info(f"Updated cache for {name}=={version} (TTL: {ttl} seconds)")

        # Update dependency records in the store
        store.update_dependency_vulnerability(
            name, version, is_vulnerable=has_vulns, vulnerability_ids=vuln_ids
        )
        if has_vulns:
            logger.info(
                f"Found {len(vuln_ids)} vulnerabilities for {name}=={version}. Updated store."
            )


def start():
    logger.info("Adding scheduled_vulnerability_scan job to scheduler")
    scheduler.add_job(
        scheduled_vulnerability_scan,
        "interval",
        seconds=TTL_CRITICAL,
        id="scheduled_vulnerability_scan",
        replace_existing=True,
    )
    scheduler.start()


def shutdown():
    """Shuts down the scheduler."""
    scheduler.shutdown()
