import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash password menggunakan Argon2id."""
    return password_hasher.hash(password)


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    """Memverifikasi password terhadap hash."""
    try:
        return password_hasher.verify(
            password_hash,
            password,
        )
    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def generate_session_token() -> str:
    """Membuat token sesi acak yang sulit ditebak."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Menghasilkan SHA-256 hash dari token."""
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def generate_csrf_token() -> str:
    """Membuat token CSRF acak."""
    return secrets.token_urlsafe(32)
