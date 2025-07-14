import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from packaging.requirements import Requirement
from app.services import osv
from app.models import OSVVulnerability, QueryVulnerabilities, OSVBatchResponse
from app.models.osv import Severity, AffectedPackage

# --- Unit tests for _extract_highest_severity and _calculate_ttl ---
def make_vuln(top_sev=None, aff_sev=None):
    sev = [Severity(type=top_sev, score='9.0')] if top_sev else None
    aff = [AffectedPackage(package={"ecosystem": "PyPI", "name": "foo"}, severity=[Severity(type=aff_sev, score='8.0')] if aff_sev else None)]
    return OSVVulnerability(id='V1', severity=sev, affected=aff)

def test_extract_highest_severity_top():
    v = make_vuln(top_sev='HIGH')
    assert osv._extract_highest_severity([v]) == 'HIGH'

def test_extract_highest_severity_affected():
    v = make_vuln(aff_sev='CRITICAL')
    assert osv._extract_highest_severity([v]) == 'CRITICAL'

def test_extract_highest_severity_mixed():
    v1 = make_vuln(top_sev='LOW')
    v2 = make_vuln(aff_sev='MODERATE')
    assert osv._extract_highest_severity([v1, v2]) == 'MODERATE'

def test_extract_highest_severity_none():
    v = OSVVulnerability(id='V2', severity=None, affected=None)
    assert osv._extract_highest_severity([v]) == 'LOW'

def test_calculate_ttl():
    v = make_vuln(top_sev='CRITICAL')
    assert osv._calculate_ttl([v]) == osv.TTL_CRITICAL
    v = make_vuln(top_sev='HIGH')
    assert osv._calculate_ttl([v]) == osv.TTL_HIGH
    v = make_vuln(top_sev='MODERATE')
    assert osv._calculate_ttl([v]) == osv.TTL_MODERATE
    v = make_vuln(top_sev='LOW')
    assert osv._calculate_ttl([v]) == osv.TTL_NONE
    assert osv._calculate_ttl([]) == osv.TTL_NONE

# --- Async tests for query_osv_batch ---
@pytest.mark.asyncio
async def test_query_osv_batch_cache_miss(monkeypatch):
    req = Requirement('foo==1.0.0')
    # Patch cache: always miss, then set
    cache_mock = MagicMock()
    cache_mock.get = AsyncMock(return_value=None)
    cache_mock.add_if_not_exists = AsyncMock(return_value=True)
    cache_mock.set = AsyncMock()
    cache_mock.wait_for_ready = AsyncMock(return_value=None)
    monkeypatch.setattr(osv, 'cache', cache_mock)
    # Patch httpx
    vuln = make_vuln(top_sev='HIGH')
    qv = QueryVulnerabilities(vulns=[vuln])
    batch = OSVBatchResponse(results=[qv])
    class FakeResp:
        def raise_for_status(self): pass
        def json(self): return batch.model_dump()
    client_mock = MagicMock()
    client_mock.post = AsyncMock(return_value=FakeResp())
    async_cm = MagicMock()
    async_cm.__aenter__ = AsyncMock(return_value=client_mock)
    async_cm.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(osv.httpx, 'AsyncClient', MagicMock(return_value=async_cm))
    out = await osv.query_osv_batch([req])
    assert isinstance(out, OSVBatchResponse)
    assert out.results[0].vulns is not None
    assert out.results[0].vulns[0].severity is not None
    assert out.results[0].vulns[0].severity[0].type == 'HIGH'

@pytest.mark.asyncio
async def test_query_osv_batch_cache_hit_fresh(monkeypatch):
    req = Requirement('bar==2.0.0')
    qv = QueryVulnerabilities(vulns=[make_vuln(top_sev='LOW')])
    entry = osv.CacheEntry(status='ready', data=qv, expiry_timestamp=9999999999)
    cache_mock = MagicMock()
    cache_mock.get = AsyncMock(return_value=entry)
    cache_mock.add_if_not_exists = AsyncMock()
    cache_mock.set = AsyncMock()
    cache_mock.wait_for_ready = AsyncMock()
    monkeypatch.setattr(osv, 'cache', cache_mock)
    out = await osv.query_osv_batch([req])
    assert out.results[0].vulns is not None
    assert out.results[0].vulns[0].severity is not None
    assert out.results[0].vulns[0].severity[0].type == 'LOW'

@pytest.mark.asyncio
async def test_query_osv_batch_cache_hit_expired(monkeypatch):
    req = Requirement('baz==3.0.0')
    qv = QueryVulnerabilities(vulns=[make_vuln(top_sev='MODERATE')])
    entry = osv.CacheEntry(status='ready', data=qv, expiry_timestamp=0)
    cache_mock = MagicMock()
    cache_mock.get = AsyncMock(return_value=entry)
    cache_mock.add_if_not_exists = AsyncMock(return_value=True)
    cache_mock.set = AsyncMock()
    cache_mock.wait_for_ready = AsyncMock()
    monkeypatch.setattr(osv, 'cache', cache_mock)
    # Patch httpx to not actually call
    class FakeResp:
        def raise_for_status(self): pass
        def json(self): return OSVBatchResponse(results=[qv]).model_dump()
    client_mock = MagicMock()
    client_mock.post = AsyncMock(return_value=FakeResp())
    async_cm = MagicMock()
    async_cm.__aenter__ = AsyncMock(return_value=client_mock)
    async_cm.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(osv.httpx, 'AsyncClient', MagicMock(return_value=async_cm))
    out = await osv.query_osv_batch([req])
    assert out.results[0].vulns is not None
    assert out.results[0].vulns[0].severity is not None
    assert out.results[0].vulns[0].severity[0].type == 'MODERATE'

@pytest.mark.asyncio
async def test_query_osv_batch_cache_fetching(monkeypatch):
    req = Requirement('qux==4.0.0')
    qv = QueryVulnerabilities(vulns=[make_vuln(top_sev='CRITICAL')])
    cache_mock = MagicMock()
    cache_mock.get = AsyncMock(return_value=osv.CacheEntry(status='fetching'))
    cache_mock.add_if_not_exists = AsyncMock()
    cache_mock.set = AsyncMock()
    cache_mock.wait_for_ready = AsyncMock(return_value=qv)
    monkeypatch.setattr(osv, 'cache', cache_mock)
    out = await osv.query_osv_batch([req])
    assert out.results[0].vulns is not None
    assert out.results[0].vulns[0].severity is not None
    assert out.results[0].vulns[0].severity[0].type == 'CRITICAL'

@pytest.mark.asyncio
async def test_query_osv_batch_no_vulns(monkeypatch):
    req = Requirement('empty==0.0.1')
    qv = QueryVulnerabilities(vulns=[])
    entry = osv.CacheEntry(status='ready', data=qv, expiry_timestamp=9999999999)
    cache_mock = MagicMock()
    cache_mock.get = AsyncMock(return_value=entry)
    cache_mock.add_if_not_exists = AsyncMock()
    cache_mock.set = AsyncMock()
    cache_mock.wait_for_ready = AsyncMock()
    monkeypatch.setattr(osv, 'cache', cache_mock)
    out = await osv.query_osv_batch([req])
    assert out.results[0].vulns == [] 