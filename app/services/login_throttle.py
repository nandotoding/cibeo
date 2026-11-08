
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DBSession

from app.config import SECRET_KEY
from app.models.auth import LoginAttempt


MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_MINUTES = 15
LOGIN_LOCK_MINUTES = 15


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_login_key(username: str, ip_address: str) -> str:
    """
    Membuat identitas login berbasis HMAC.
    Username dan IP tidak disimpan dalam bentuk asli.
    """
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY belum dikonfigurasi")

    normalized_username = username.strip().lower()
    raw_key = f"{normalized_username}:{ip_address}"

    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def is_login_locked(db: DBSession, key_hash: str) -> bool:
    now = utc_now()

    statement = select(LoginAttempt.id).where(
        LoginAttempt.key_hash == key_hash,
        LoginAttempt.locked_until > now,
    )

    return db.scalar(statement) is not None


def record_login_failure(
    db: DBSession,
    key_hash: str,
) -> dict:
    """
    Mencatat kegagalan login secara atomik menggunakan PostgreSQL UPSERT.
    """
    now = utc_now()
    window_expired = now - timedelta(minutes=LOGIN_WINDOW_MINUTES)

    locked_condition = and_(
        LoginAttempt.locked_until.is_not(None),
        LoginAttempt.locked_until > now,
    )

    expired_condition = LoginAttempt.window_started_at <= window_expired

    statement = insert(LoginAttempt).values(
        key_hash=key_hash,
        failure_count=1,
        window_started_at=now,
        locked_until=None,
        updated_at=now,
    )

    statement = statement.on_conflict_do_update(
        index_elements=[LoginAttempt.key_hash],
        set_={
            "failure_count": case(
                (locked_condition, LoginAttempt.failure_count),
                (expired_condition, 1),
                else_=LoginAttempt.failure_count + 1,
            ),
            "window_started_at": case(
                (locked_condition, LoginAttempt.window_started_at),
                (expired_condition, now),
                else_=LoginAttempt.window_started_at,
            ),
            "locked_until": case(
                (locked_condition, LoginAttempt.locked_until),
                (expired_condition, None),
                (
                    LoginAttempt.failure_count + 1 >= MAX_LOGIN_FAILURES,
                    now + timedelta(minutes=LOGIN_LOCK_MINUTES),
                ),
                else_=None,
            ),
            "updated_at": now,
        },
    ).returning(
        LoginAttempt.failure_count,
        LoginAttempt.locked_until,
    )

    result = db.execute(statement).one()
    db.commit()

    return {
        "failure_count": result.failure_count,
        "locked_until": result.locked_until,
        "is_locked": (
            result.locked_until is not None
            and result.locked_until > now
        ),
    }


def clear_login_failures(db: DBSession, key_hash: str) -> None:
    """
    Menghapus catatan kegagalan setelah login berhasil.
    """
    statement = delete(LoginAttempt).where(
        LoginAttempt.key_hash == key_hash
    )

    db.execute(statement)
    db.commit()

