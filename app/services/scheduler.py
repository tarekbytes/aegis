import logging
from typing import TYPE_CHECKING, List, Dict, Set, Tuple

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
    Periodically queries all unique dependencies in the store against OSV.
    The OSV module itself handles caching, so this scheduler simply acts
    as a periodic trigger to refresh the data.
    """
    logger.info("Starting scheduled vulnerability scan for all dependencies.")
    all_deps: List[Dict[str, str]] = store.get_all_dependencies()
    if not all_deps:
        logger.info("No dependencies in the store to scan.")
        return

    unique_deps: Set[Tuple[str, str]] = {
        (dep["name"], dep["version"]) for dep in all_deps
    }
    unique_deps_reqs = [
        Requirement(f"{name}=={version}") for name, version in unique_deps
    ]

    if not unique_deps_reqs:
        logger.info("No unique dependencies found to scan.")
        return

    logger.info(f"Querying OSV for {len(unique_deps_reqs)} unique dependencies.")
    osv_results: OSVBatchResponse = await query_osv_batch(unique_deps_reqs)

    # Update the store with the latest results
    for req, query_vulns in zip(unique_deps_reqs, osv_results.results):
        version = str(next(iter(req.specifier)).version)
        name = req.name.lower()

        has_vulns = query_vulns.vulns is not None and len(query_vulns.vulns) > 0
        vuln_ids = [v.id for v in query_vulns.vulns] if has_vulns else []

        store.update_dependency_vulnerability(
            name, version, is_vulnerable=has_vulns, vulnerability_ids=vuln_ids
        )
    logger.info("Scheduled vulnerability scan finished.")


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
