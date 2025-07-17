from apscheduler.schedulers.asyncio import AsyncIOScheduler
from pytz import utc
import time
from packaging.requirements import Requirement
import logging

from app.data import store
from app.models.osv import OSVBatchResponse
from app.modules.osv import query_osv_batch, _calculate_ttl
from app.services.cache import cache, CacheEntry
from app.modules.osv import TTL_CRITICAL

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=utc)

async def scheduled_vulnerability_scan():
    """
    Periodically scans all unique dependencies in the store, checks for stale
    cache entries, and re-queries OSV for the latest vulnerability data.
    """
    # 1. Get all unique dependencies in use (name and version)
    all_deps = store.get_all_dependencies()
    unique_deps = { (dep['name'], dep['version']) for dep in all_deps }

    # 2. Filter for stale cache entries
    stale_deps_reqs: list[Requirement] = []
    for name, version in unique_deps:
        cache_key = f"{name.lower()}@{version}"
        entry = await cache.get(cache_key)
        # Check if entry is missing or expired
        if not entry or (entry.expiry_timestamp and time.time() > entry.expiry_timestamp):
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
        ttl = _calculate_ttl(query_vulns.vulns)
        new_entry = CacheEntry(status='ready', data=query_vulns, expiry_timestamp=time.time() + ttl)
        await cache.set(cache_key, new_entry)
        logger.info(f"Updated cache for {name}=={version} (TTL: {ttl} seconds)")
        # Properly clear the refresh entry
        async with cache._lock:
            cache._store.pop(cache_key + ':refresh', None)

        # Update dependency records in the store
        store.update_dependency_vulnerability(name, version, has_vulns, vuln_ids)
        if has_vulns:
            logger.info(f"Found {len(vuln_ids)} vulnerabilities for {name}=={version}. Updated store.")


def start():
    logger.info("Adding scheduled_vulnerability_scan job to scheduler")
    scheduler.add_job(
        scheduled_vulnerability_scan,
        'interval',
        seconds= TTL_CRITICAL,
        id='scheduled_vulnerability_scan',
        replace_existing=True
    )
    scheduler.start()

def shutdown():
    """Shuts down the scheduler."""
    scheduler.shutdown()
