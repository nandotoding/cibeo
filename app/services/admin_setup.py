
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.models.auth import AdminAccount
from app.services.security import hash_password


def ensure_admin_account(
    db: DBSession,
    username: str,
    password: str,
) -> bool:
    username = username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_]{3,50}", username):
        raise ValueError(
            "Username admin harus 3-50 karakter "
            "dan hanya menggunakan huruf kecil, angka, atau underscore."
        )

    if len(password) < 12 or len(password) > 128:
        raise ValueError(
            "Password admin harus 12-128 karakter."
        )

    existing_admin = db.scalar(
        select(AdminAccount).where(
            AdminAccount.username == username
        )
    )

    if existing_admin:
        return False

    admin = AdminAccount(
        username=username,
        password_hash=hash_password(password),
    )

    db.add(admin)

    try:
        db.commit()
        return True

    except IntegrityError:
        db.rollback()

        # Akun mungkin dibuat oleh proses lain secara bersamaan.
        existing_admin = db.scalar(
            select(AdminAccount).where(
                AdminAccount.username == username
            )
        )

        if existing_admin:
            return False

        raise

