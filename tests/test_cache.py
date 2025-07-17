import asyncio
import pytest
from app.services.cache import cache, CacheEntry

@pytest.mark.asyncio
async def test_add_if_not_exists_and_get():
    key = 'dep@1.0.0'
    entry = CacheEntry(status='fetching')
    added = await cache.add_if_not_exists(key, entry)
    assert added
    fetched = await cache.get(key)
    assert fetched is not None
    assert fetched.status == 'fetching'
    # Try to add again
    added_again = await cache.add_if_not_exists(key, CacheEntry(status='fetching'))
    assert not added_again

@pytest.mark.asyncio
async def test_set_and_get():
    key = 'dep@2.0.0'
    entry = CacheEntry(status='ready', data={'foo': 'bar'}, expiry_timestamp=123456.0)
    await cache.set(key, entry)
    fetched = await cache.get(key)
    assert fetched is not None
    assert fetched.status == 'ready'
    assert fetched.data == {'foo': 'bar'}
    assert fetched.expiry_timestamp == 123456.0

@pytest.mark.asyncio
async def test_wait_for_ready_success():
    key = 'dep@3.0.0'
    entry = CacheEntry(status='fetching')
    await cache.set(key, entry)
    async def set_ready():
        await asyncio.sleep(0.2)
        await cache.set(key, CacheEntry(status='ready', data='vuln', expiry_timestamp=999999.0))
    asyncio.create_task(set_ready())
    data = await cache.wait_for_ready(key, timeout=1.0, poll_interval=0.05)
    assert data == 'vuln'

@pytest.mark.asyncio
async def test_wait_for_ready_timeout():
    key = 'dep@4.0.0'
    entry = CacheEntry(status='fetching')
    await cache.set(key, entry)
    data = await cache.wait_for_ready(key, timeout=0.3, poll_interval=0.05)
    assert data is None
