
import hashlib
import hmac
import secrets
import time

from app.config import SECRET_KEY


PRE_AUTH_CSRF_MAX_AGE = 2 * 60 * 60  # 2 jam


def generate_pre_auth_csrf_token() -> str:
    """
    Membuat token CSRF sementara sebelum pengguna login.
    Token ditandatangani menggunakan SECRET_KEY.
    """
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY belum dikonfigurasi")

    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)

    message = f"{timestamp}.{nonce}"

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{message}.{signature}"


def verify_pre_auth_csrf_token(
    cookie_token: str | None,
    submitted_token: str | None,
) -> bool:
    """
    Memvalidasi token dari cookie dan header.
    """
    if not SECRET_KEY or not cookie_token or not submitted_token:
        return False

    # Cookie dan header harus berisi token yang sama.
    if not hmac.compare_digest(cookie_token, submitted_token):
        return False

    parts = cookie_token.split(".")

    if len(parts) != 3:
        return False

    timestamp, nonce, submitted_signature = parts

    try:
        issued_at = int(timestamp)
    except ValueError:
        return False

    now = int(time.time())

    # Tolak token yang berasal dari masa depan atau sudah kedaluwarsa.
    if issued_at > now + 60:
        return False

    if now - issued_at > PRE_AUTH_CSRF_MAX_AGE:
        return False

    message = f"{timestamp}.{nonce}"

    expected_signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected_signature,
        submitted_signature,
    )

