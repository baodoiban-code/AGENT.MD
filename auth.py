"""Small, dependency-free JWT authentication helpers using HS256.

Keep ``secret_key`` outside source control, for example in an environment
variable. Password hashes created by ``hash_password`` can be stored in a
database and supplied to ``login``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import timedelta
from typing import Any, Mapping


ALGORITHM = "HS256"
DEFAULT_PASSWORD_ITERATIONS = 600_000


class AuthenticationError(ValueError):
    """Raised when credentials cannot be authenticated."""


class InvalidTokenError(ValueError):
    """Raised when a JWT is malformed, invalid, or expired."""


def hash_password(
    password: str, *, iterations: int = DEFAULT_PASSWORD_ITERATIONS
) -> str:
    """Return a salted PBKDF2-SHA256 password hash suitable for storage."""
    if not password:
        raise ValueError("Password must not be empty.")
    if iterations < 1:
        raise ValueError("Iterations must be positive.")

    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return "$".join(
        (
            "pbkdf2_sha256",
            str(iterations),
            _base64url_encode(salt),
            _base64url_encode(derived_key),
        )
    )


def verify_password(password: str, stored_password_hash: str) -> bool:
    """Verify a password against a value returned by ``hash_password``."""
    try:
        (
            scheme,
            iteration_text,
            salt_text,
            expected_hash,
        ) = stored_password_hash.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        salt = _base64url_decode(salt_text)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(_base64url_encode(actual_hash), expected_hash)


def create_access_token(
    subject: str,
    secret_key: str,
    *,
    expires_in: timedelta = timedelta(hours=1),
    additional_claims: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> str:
    """Create a signed HS256 JWT with ``sub``, ``iat``, and ``exp`` claims."""
    if not subject:
        raise ValueError("Subject must not be empty.")
    if not secret_key:
        raise ValueError("Secret key must not be empty.")
    if expires_in.total_seconds() <= 0:
        raise ValueError("Token lifetime must be positive.")

    issued_at = int(time.time()) if now is None else now
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": issued_at,
        "exp": issued_at + int(expires_in.total_seconds()),
    }
    if additional_claims:
        protected_claims = {"sub", "iat", "exp"}
        overlap = protected_claims.intersection(additional_claims)
        if overlap:
            message = "Additional claims cannot replace: "
            raise ValueError(message + ", ".join(sorted(overlap)))
        payload.update(additional_claims)

    return encode_token(payload, secret_key)


def encode_token(payload: Mapping[str, Any], secret_key: str) -> str:
    """Serialize and sign a payload as a compact JWT using HS256."""
    if not secret_key:
        raise ValueError("Secret key must not be empty.")
    header = {"alg": ALGORITHM, "typ": "JWT"}
    encoded_header = _json_base64url_encode(header)
    encoded_payload = _json_base64url_encode(payload)
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(
        secret_key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_base64url_encode(signature)}"


def decode_token(
    token: str, secret_key: str, *, now: int | None = None
) -> dict[str, Any]:
    """Validate an HS256 JWT and return its payload.

    Raises ``InvalidTokenError`` when validation fails.
    """
    if not secret_key:
        raise ValueError("Secret key must not be empty.")
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = _json_base64url_decode(encoded_header)
        payload = _json_base64url_decode(encoded_payload)
        valid_algorithm = header.get("alg") == ALGORITHM
        valid_type = header.get("typ") == "JWT"
        if not valid_algorithm or not valid_type:
            raise InvalidTokenError("Unsupported token header.")
        if not isinstance(payload, dict):
            raise InvalidTokenError("Token payload must be an object.")

        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            secret_key.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        received_signature = _base64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, received_signature):
            raise InvalidTokenError("Invalid token signature.")

        expiration = payload.get("exp")
        is_numeric_expiration = isinstance(expiration, (int, float))
        if isinstance(expiration, bool) or not is_numeric_expiration:
            raise InvalidTokenError("Token must contain a numeric expiration.")
        current_time = time.time() if now is None else now
        if current_time >= expiration:
            raise InvalidTokenError("Token has expired.")
    except (
        AttributeError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        if isinstance(error, InvalidTokenError):
            raise
        raise InvalidTokenError("Malformed token.") from error

    return payload


def login(
    username: str,
    password: str,
    user_password_hashes: Mapping[str, str],
    secret_key: str,
    *,
    expires_in: timedelta = timedelta(hours=1),
) -> str:
    """Authenticate a user and return a signed access token."""
    stored_password_hash = user_password_hashes.get(username)
    if stored_password_hash is None or not verify_password(
        password, stored_password_hash
    ):
        raise AuthenticationError("Invalid username or password.")
    return create_access_token(username, secret_key, expires_in=expires_in)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(
        (value + padding).encode("ascii"), altchars=b"-_", validate=True
    )


def _json_base64url_encode(value: Mapping[str, Any]) -> str:
    serialized = json.dumps(
        value, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return _base64url_encode(serialized)


def _json_base64url_decode(value: str) -> dict[str, Any]:
    decoded = _base64url_decode(value).decode("utf-8")
    result = json.loads(decoded)
    if not isinstance(result, dict):
        raise InvalidTokenError("JWT section must be an object.")
    return result

