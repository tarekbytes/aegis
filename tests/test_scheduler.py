from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.osv import OSVBatchResponse, OSVVulnerability, QueryVulnerabilities
from app.services.scheduler import scheduled_vulnerability_scan


@pytest.mark.asyncio
@patch("app.services.scheduler.store", new_callable=MagicMock)
@patch("app.services.scheduler.query_osv_batch", new_callable=AsyncMock)
async def test_scheduled_vulnerability_scan(mock_query_osv, mock_store):
    """
    Tests that the scheduler correctly calls the OSV module and updates the store.
    """
    # Arrange
    mock_store.get_all_dependencies.return_value = [
        {"name": "requests", "version": "2.25.1"},
        {"name": "django", "version": "3.2.12"},
    ]

    mock_osv_response = OSVBatchResponse(
        results=[
            QueryVulnerabilities(
                vulns=[
                    OSVVulnerability(
                        id="CVE-2023-1234", modified="2023-01-01T00:00:00Z"
                    )
                ]
            ),
            QueryVulnerabilities(vulns=[]),
        ]
    )
    mock_query_osv.return_value = mock_osv_response

    # Act
    await scheduled_vulnerability_scan()

    # Assert
    mock_store.get_all_dependencies.assert_called_once()
    mock_query_osv.assert_called_once()

    # Verify that the store was updated correctly
    assert mock_store.update_dependency_vulnerability.call_count == 2
    mock_store.update_dependency_vulnerability.assert_any_call(
        "requests", "2.25.1", is_vulnerable=True, vulnerability_ids=["CVE-2023-1234"]
    )
    mock_store.update_dependency_vulnerability.assert_any_call(
        "django", "3.2.12", is_vulnerable=False, vulnerability_ids=[]
    )


@pytest.mark.asyncio
@patch("app.services.scheduler.store", new_callable=MagicMock)
@patch("app.services.scheduler.query_osv_batch", new_callable=AsyncMock)
async def test_scheduled_vulnerability_scan_no_deps(mock_query_osv, mock_store):
    """
    Tests that the scheduler exits gracefully when there are no dependencies.
    """
    # Arrange
    mock_store.get_all_dependencies.return_value = []

    # Act
    await scheduled_vulnerability_scan()

    # Assert
    mock_store.get_all_dependencies.assert_called_once()
    mock_query_osv.assert_not_called()
    mock_store.update_dependency_vulnerability.assert_not_called()
