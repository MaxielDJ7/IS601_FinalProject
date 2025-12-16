import pytest
from unittest.mock import AsyncMock, patch
from app.auth import redis as redis_module

@pytest.mark.asyncio
async def test_get_redis_singleton():
    mock_redis = AsyncMock()

    with patch("app.auth.redis.Redis.from_url", return_value=mock_redis):
        # First call creates Redis
        redis1 = await redis_module.get_redis()
        # Second call reuses it
        redis2 = await redis_module.get_redis()

        assert redis1 is redis2

@pytest.mark.asyncio
async def test_add_to_blacklist():
    mock_redis = AsyncMock()

    with patch("app.auth.redis.get_redis", return_value=mock_redis):
        await redis_module.add_to_blacklist("jti123", 3600)

        mock_redis.set.assert_awaited_once_with(
            "blacklist:jti123",
            "1",
            ex=3600,
        )

@pytest.mark.asyncio
async def test_is_blacklisted_true():
    mock_redis = AsyncMock()
    mock_redis.exists.return_value = 1

    with patch("app.auth.redis.get_redis", return_value=mock_redis):
        result = await redis_module.is_blacklisted("jti123")

        assert result
        mock_redis.exists.assert_awaited_once_with("blacklist:jti123")

@pytest.mark.asyncio
async def test_is_blacklisted_false():
    mock_redis = AsyncMock()
    mock_redis.exists.return_value = 0

    with patch("app.auth.redis.get_redis", return_value=mock_redis):
        result = await redis_module.is_blacklisted("jti123")

        assert not result
