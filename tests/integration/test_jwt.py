
from datetime import timedelta
from fastapi import HTTPException
from jose import jwt as jose_jwt
from app.auth import jwt
from app.core.config import get_settings
from uuid import uuid4
from unittest.mock import AsyncMock, patch
import pytest
from app.auth.dependencies import get_current_user
from app.schemas.token import TokenType

settings = get_settings



def test_password_hash_and_verify():
    password = "SecurePass123!"
    hashed = jwt.get_password_hash(password)

    assert hashed != password
    assert jwt.verify_password(password, hashed) is True
    assert jwt.verify_password("wrong", hashed) is False



def test_create_token_encode_failure():
    with patch("app.auth.jwt.jwt.encode", side_effect=Exception("boom")):
        with pytest.raises(HTTPException) as exc:
            jwt.create_token("user123", TokenType.ACCESS)

    assert exc.value.status_code == 500

@pytest.mark.asyncio
async def test_decode_token_valid():
    token = jwt.create_token("user123", TokenType.ACCESS)

    payload = await jwt.decode_token(token, TokenType.ACCESS)

    assert payload["sub"] == "user123"


@pytest.mark.asyncio
async def test_decode_token_expired():
    token = jwt.create_token(
        "user123",
        TokenType.ACCESS,
        expires_delta=timedelta(seconds=-1),
    )

    with pytest.raises(HTTPException) as exc:
        await jwt.decode_token(token, TokenType.ACCESS)

    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()

@pytest.mark.asyncio
async def test_decode_token_invalid_jwt():
    with pytest.raises(HTTPException) as exc:
        await jwt.decode_token("bad.token", TokenType.ACCESS)

    assert exc.value.status_code == 401
    assert "validate credentials" in exc.value.detail.lower()


