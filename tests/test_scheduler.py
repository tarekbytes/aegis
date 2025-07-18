import time
from unittest.mock import AsyncMock, patch, MagicMock

from packaging.requirements import Requirement
import pytest

from app.data import store
from app.models.osv import (
    OSVBatchResponse,
    OSVVulnerability,
    QueryVulnerabilities,
    Severity,
)
from app.services.cache import CacheEntry, InMemoryAsyncCache
from app.services.scheduler import scheduled_vulnerability_scan


@pytest.fixture
def mock_cache():
    """Provides a mock cache instance for each test."""
    return InMemoryAsyncCache()


@pytest.mark.asyncio
async def test_scheduled_vulnerability_scan(mock_cache):
    """
    Tests the scheduled vulnerability scan logic.
    - Mocks the OSV API response dynamically.
    - Sets up dependencies with various cache states (stale, fresh, missing).
    - Verifies that only stale dependencies are scanned.
    - Verifies that the store is updated correctly.
    """
    # 1. Arrange
    # Patch the global cache instance and store used by the scheduler
    with (
        patch("app.services.scheduler.cache", mock_cache),
        patch("app.services.scheduler.store", new_callable=MagicMock) as mock_store,
    ):
        # Set up a side effect for get_all_dependencies to return our test data
        mock_store.get_all_dependencies.return_value = [
            {"name": "stale-dep", "version": "1.0.0"},
            {"name": "fresh-dep", "version": "1.0.0"},
            {"name": "missing-dep", "version": "1.0.0"},
        ]

        # Set up cache states for the dependencies
        stale_entry = CacheEntry(
            status="ready",
            data=QueryVulnerabilities(vulns=[]),
            expiry_timestamp=time.time() - 3600,
        )
        await mock_cache.set("stale-dep@1.0.0", stale_entry)
        fresh_entry = CacheEntry(
            status="ready",
            data=QueryVulnerabilities(vulns=[]),
            expiry_timestamp=time.time() + 3600,
        )
        await mock_cache.set("fresh-dep@1.0.0", fresh_entry)

        # We expect the batch query to be called only for stale and missing dependencies
        expected_reqs = {
            Requirement("stale-dep==1.0.0"),
            Requirement("missing-dep==1.0.0"),
        }

        # This side effect dynamically builds the response based on the input
        async def mock_osv_side_effect(reqs: list[Requirement]):
            results = []
            for req in reqs:
                if req.name == "stale-dep":
                    results.append(
                        QueryVulnerabilities(
                            vulns=[
                                OSVVulnerability(
                                    id="CVE-2023-1234", modified="2023-01-01T00:00:00Z"
                                )
                            ]
                        )
                    )
                else:
                    results.append(QueryVulnerabilities(vulns=[]))
            return OSVBatchResponse(results=results)

        with patch(
            "app.services.scheduler.query_osv_batch", new_callable=AsyncMock
        ) as mock_query_osv:
            mock_query_osv.side_effect = mock_osv_side_effect

            # 2. Act
            await scheduled_vulnerability_scan()

            # 3. Assert
            # Verify OSV was queried with the correct dependencies
            mock_query_osv.assert_called_once()
            called_args = mock_query_osv.call_args[0][0]
            assert {str(r) for r in called_args} == {str(r) for r in expected_reqs}

            # Verify store was updated for both dependencies that were scanned
            assert mock_store.update_dependency_vulnerability.call_count == 2
            mock_store.update_dependency_vulnerability.assert_any_call(
                "stale-dep",
                "1.0.0",
                is_vulnerable=True,
                vulnerability_ids=["CVE-2023-1234"],
            )
            mock_store.update_dependency_vulnerability.assert_any_call(
                "missing-dep", "1.0.0", is_vulnerable=False, vulnerability_ids=[]
            )


@pytest.mark.asyncio
async def test_scheduled_vulnerability_scan_unknown_severity(mock_cache):
    """
    Tests that the scan handles unknown severities gracefully without crashing.
    """
    # 1. Arrange
    with (
        patch("app.services.scheduler.cache", mock_cache),
        patch("app.services.scheduler.store", new_callable=MagicMock) as mock_store,
    ):
        mock_store.get_all_dependencies.return_value = [
            {"name": "stale-dep", "version": "1.0.0"}
        ]
        await mock_cache.set(
            "stale-dep@1.0.0",
            CacheEntry(
                status="ready",
                data=QueryVulnerabilities(vulns=[]),
                expiry_timestamp=time.time() - 3600,
            ),
        )

        async def mock_osv_side_effect(reqs: list[Requirement]):
            vuln = OSVVulnerability(
                id="CVE-2023-9999",
                modified="2023-01-01T00:00:00Z",
                severity=[Severity(type="UNKNOWN", score="0.0")],
            )
            return OSVBatchResponse(results=[QueryVulnerabilities(vulns=[vuln])])

        with patch(
            "app.services.scheduler.query_osv_batch", new_callable=AsyncMock
        ) as mock_query_osv:
            mock_query_osv.side_effect = mock_osv_side_effect

            # 2. Act & 3. Assert
            # The test passes if this does not raise a ValueError
            await scheduled_vulnerability_scan()
            mock_store.update_dependency_vulnerability.assert_called_once_with(
                "stale-dep",
                "1.0.0",
                is_vulnerable=True,
                vulnerability_ids=["CVE-2023-9999"],
            )


@pytest.mark.asyncio
async def test_scheduled_vulnerability_scan_no_stale_deps(mock_cache):
    """
    Tests that the scan exits early if there are no stale dependencies.
    """
    # 1. Arrange
    with patch("app.services.scheduler.cache", mock_cache):
        store.add_project("Test Project", "A test project")
        deps_to_add = [
            {
                "name": "fresh-dep",
                "version": "1.0.0",
                "is_vulnerable": False,
                "vulnerability_ids": [],
            },
        ]
        store.add_dependencies(1, deps_to_add)

        fresh_entry = CacheEntry(
            status="ready",
            data=QueryVulnerabilities(vulns=[]),
            expiry_timestamp=time.time() + 3600,
        )
        await mock_cache.set("fresh-dep@1.0.0", fresh_entry)

        with patch(
            "app.services.scheduler.query_osv_batch", new_callable=AsyncMock
        ) as mock_query_osv:
            # 2. Act
            await scheduled_vulnerability_scan()

            # 3. Assert
            mock_query_osv.assert_not_called()


def test_scheduler_start_and_shutdown():
    """
    Tests the start and shutdown functions of the scheduler.
    """
    with (
        patch("app.services.scheduler.scheduler.add_job") as mock_add_job,
        patch("app.services.scheduler.scheduler.start") as mock_start,
        patch("app.services.scheduler.scheduler.shutdown") as mock_shutdown,
    ):
        from app.services import scheduler as scheduler_service

        # Test start
        scheduler_service.start()
        mock_add_job.assert_called_once()
        mock_start.assert_called_once()

        # Test shutdown
        scheduler_service.shutdown()
        mock_shutdown.assert_called_once()
