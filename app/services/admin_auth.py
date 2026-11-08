
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.models.auth import AdminAccount
from app.services.security import verify_password
from app.services.login_throttle import (
    make_login_key,
    is_login_locked,
    record_login_failure,
    clear_login_failures,
)


class InvalidAdminCredentials(Exception):
    pass


class AdminLoginThrottled(Exception):
    pass


def authenticate_admin(
    db: DBSession,
    username: str,
    password: str,
    ip_address: str,
) -> AdminAccount:
    normalized_username = username.strip().lower()

    key_hash = make_login_key(
        normalized_username,
        ip_address,
    )

    if is_login_locked(db, key_hash):
        raise AdminLoginThrottled

    admin = db.scalar(
        select(AdminAccount).where(
            AdminAccount.username == normalized_username
        )
    )

    if admin is None or not verify_password(
        password,
        admin.password_hash,
    ):
        result = record_login_failure(db, key_hash)

        if result["is_locked"]:
            raise AdminLoginThrottled

        raise InvalidAdminCredentials

    clear_login_failures(db, key_hash)

    return admin

