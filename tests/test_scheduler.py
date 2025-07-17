import pytest
import time
from unittest.mock import AsyncMock, patch
from packaging.requirements import Requirement

from app.services.scheduler import scheduled_vulnerability_scan
from app.services.cache import CacheEntry, InMemoryAsyncCache
from app.data import store
from app.models.osv import QueryVulnerabilities, OSVBatchResponse, OSVVulnerability

@pytest.fixture(autouse=True)
def clean_stores():
    """Cleans the stores before each test."""
    store.clear_projects_store()
    store.clear_dependencies_store()
    yield


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
    - Verifies that the cache and store are updated correctly.
    """
    # 1. Arrange
    # Patch the global cache instance used by the scheduler
    with patch('app.services.scheduler.cache', mock_cache):
        # Add a project and some dependencies
        store.add_project("Test Project", "A test project")
        deps_to_add = [
            {"name": "stale-dep", "version": "1.0.0", "is_vulnerable": False, "vulnerability_ids": []},
            {"name": "fresh-dep", "version": "1.0.0", "is_vulnerable": False, "vulnerability_ids": []},
            {"name": "missing-dep", "version": "1.0.0", "is_vulnerable": False, "vulnerability_ids": []},
        ]
        store.add_dependencies(1, deps_to_add)

        # Set up cache states
        stale_entry = CacheEntry(status='ready', data=QueryVulnerabilities(vulns=[]), expiry_timestamp=time.time() - 3600)
        await mock_cache.set("stale-dep@1.0.0", stale_entry)
        fresh_entry = CacheEntry(status='ready', data=QueryVulnerabilities(vulns=[]), expiry_timestamp=time.time() + 3600)
        await mock_cache.set("fresh-dep@1.0.0", fresh_entry)

        # We expect the batch query to be called only for stale and missing dependencies
        expected_reqs = {Requirement("stale-dep==1.0.0"), Requirement("missing-dep==1.0.0")}

        # This side effect dynamically builds the response based on the input
        async def mock_osv_side_effect(reqs: list[Requirement]):
            results = []
            for req in reqs:
                if req.name == "stale-dep":
                    results.append(QueryVulnerabilities(vulns=[OSVVulnerability(id='CVE-2023-1234', modified='2023-01-01T00:00:00Z')]))
                else:
                    results.append(QueryVulnerabilities(vulns=[]))
            return OSVBatchResponse(results=results)

        with patch('app.services.scheduler.query_osv_batch', new_callable=AsyncMock) as mock_query_osv:
            mock_query_osv.side_effect = mock_osv_side_effect

            # 2. Act
            await scheduled_vulnerability_scan()

            # 3. Assert
            # Verify OSV was queried with the correct dependencies
            mock_query_osv.assert_called_once()
            called_args = mock_query_osv.call_args[0][0]
            assert {str(r) for r in called_args} == {str(r) for r in expected_reqs}

            # Verify store was updated for the vulnerable dependency
            updated_deps = store.get_dependency_details("stale-dep", "1.0.0")
            assert len(updated_deps) > 0, "Dependency 'stale-dep' not found in store"
            assert updated_deps[0]['is_vulnerable'] is True
            assert updated_deps[0]['vulnerability_ids'] == ['CVE-2023-1234']
            
            # Verify store was NOT updated for the clean dependency
            clean_deps = store.get_dependency_details("missing-dep", "1.0.0")
            assert len(clean_deps) > 0
            assert clean_deps[0]['is_vulnerable'] is False

            # Verify cache was updated for the scanned dependencies
            stale_cache_entry = await mock_cache.get("stale-dep@1.0.0")
            missing_cache_entry = await mock_cache.get("missing-dep@1.0.0")
            fresh_cache_entry = await mock_cache.get("fresh-dep@1.0.0")

            assert stale_cache_entry is not None
            assert stale_cache_entry.status == 'ready'
            assert stale_cache_entry.expiry_timestamp > time.time()
            assert stale_cache_entry.data.vulns is not None and len(stale_cache_entry.data.vulns) == 1

            assert missing_cache_entry is not None
            assert missing_cache_entry.status == 'ready'
            assert missing_cache_entry.expiry_timestamp > time.time()
            assert not (missing_cache_entry.data.vulns is not None and len(missing_cache_entry.data.vulns) > 0)
            
            # Verify fresh entry was not touched (its expiry is the same)
            assert fresh_cache_entry is not None
            assert fresh_cache_entry.expiry_timestamp == fresh_entry.expiry_timestamp


@pytest.mark.asyncio
async def test_scheduled_vulnerability_scan_no_stale_deps(mock_cache):
    """
    Tests that the scan exits early if there are no stale dependencies.
    """
    # 1. Arrange
    with patch('app.services.scheduler.cache', mock_cache):
        store.add_project("Test Project", "A test project")
        deps_to_add = [
            {"name": "fresh-dep", "version": "1.0.0", "is_vulnerable": False, "vulnerability_ids": []},
        ]
        store.add_dependencies(1, deps_to_add)

        fresh_entry = CacheEntry(status='ready', data=QueryVulnerabilities(vulns=[]), expiry_timestamp=time.time() + 3600)
        await mock_cache.set("fresh-dep@1.0.0", fresh_entry)

        with patch('app.services.scheduler.query_osv_batch', new_callable=AsyncMock) as mock_query_osv:
            # 2. Act
            await scheduled_vulnerability_scan()

            # 3. Assert
            mock_query_osv.assert_not_called()

def test_scheduler_start_and_shutdown():
    """
    Tests the start and shutdown functions of the scheduler.
    """
    with patch('app.services.scheduler.scheduler.add_job') as mock_add_job, \
         patch('app.services.scheduler.scheduler.start') as mock_start, \
         patch('app.services.scheduler.scheduler.shutdown') as mock_shutdown:

        from app.services import scheduler as scheduler_service

        # Test start
        scheduler_service.start()
        mock_add_job.assert_called_once()
        mock_start.assert_called_once()

        # Test shutdown
        scheduler_service.shutdown()
        mock_shutdown.assert_called_once() 