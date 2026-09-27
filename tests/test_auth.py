from datetime import timedelta

import pytest

from auth import (
    AuthenticationError,
    InvalidTokenError,
    create_access_token,
    decode_token,
    hash_password,
    login,
)


SECRET_KEY = "test-secret-key"


def test_login_returns_a_token_with_the_authenticated_subject() -> None:
    password = "correct horse battery staple"
    user_password_hashes = {"alice": hash_password(password)}

    token = login(
        "alice",
        password,
        user_password_hashes,
        SECRET_KEY,
    )

    assert decode_token(token, SECRET_KEY)["sub"] == "alice"


def test_login_rejects_an_invalid_password() -> None:
    user_password_hashes = {"alice": hash_password("correct password")}

    with pytest.raises(
        AuthenticationError, match="Invalid username or password"
    ):
        login("alice", "wrong password", user_password_hashes, SECRET_KEY)


def test_decode_token_rejects_an_expired_token() -> None:
    token = create_access_token(
        "alice", SECRET_KEY, expires_in=timedelta(seconds=5), now=100
    )

    with pytest.raises(InvalidTokenError, match="expired"):
        decode_token(token, SECRET_KEY, now=105)


def test_decode_token_rejects_a_modified_token() -> None:
    token = create_access_token("alice", SECRET_KEY)
    modified_token = token[:-1] + ("a" if token[-1] != "a" else "b")

    with pytest.raises(InvalidTokenError, match="signature"):
        decode_token(modified_token, SECRET_KEY)

