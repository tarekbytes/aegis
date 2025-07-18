import logging
import time
from typing import TYPE_CHECKING

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from packaging.requirements import Requirement
from pytz import utc

from app.data import store
from app.modules.osv import TTL_CRITICAL, query_osv_batch
from app.services.cache import cache

if TYPE_CHECKING:
    from app.models.osv import OSVBatchResponse

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=utc)


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

    # 4. Update store for each result
    for req, query_vulns in zip(stale_deps_reqs, osv_results.results):
        version = str(next(iter(req.specifier)).version)
        name = req.name.lower()

        has_vulns = query_vulns.vulns is not None and len(query_vulns.vulns) > 0
        vuln_ids = [v.id for v in query_vulns.vulns] if has_vulns else []

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
