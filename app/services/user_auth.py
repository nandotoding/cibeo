import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.models.auth import User
from app.services.security import hash_password, verify_password
from app.services.login_throttle import (
    make_login_key,
    is_login_locked,
    record_login_failure,
    clear_login_failures,
)


class UsernameAlreadyExists(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class LoginThrottled(Exception):
    pass


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_registration(
    full_name: str,
    username: str,
    password: str,
) -> tuple[str, str]:
    full_name = full_name.strip()
    username = normalize_username(username)

    if not full_name or len(full_name) > 150:
        raise ValueError("Nama lengkap harus berisi 1–150 karakter.")

    if not re.fullmatch(r"[a-z0-9_]{3,50}", username):
        raise ValueError(
            "Username harus terdiri dari 3–50 karakter, "
            "hanya huruf kecil, angka, dan underscore."
        )

    if len(password) < 6 or len(password) > 128:
        raise ValueError("Password harus terdiri dari 6–128 karakter.")

    return full_name, username


def register_user(
    db: DBSession,
    full_name: str,
    username: str,
    password: str,
) -> User:
    full_name, username = validate_registration(
        full_name,
        username,
        password,
    )

    user = User(
        full_name=full_name,
        username=username,
        password_hash=hash_password(password),
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise UsernameAlreadyExists

    return user


def authenticate_user(
    db: DBSession,
    username: str,
    password: str,
    ip_address: str,
) -> User:
    normalized_username = normalize_username(username)

    key_hash = make_login_key(
        normalized_username,
        ip_address,
    )

    if is_login_locked(db, key_hash):
        raise LoginThrottled

    statement = select(User).where(
        User.username == normalized_username
    )

    user = db.scalar(statement)

    if (
        user is None
        or not user.is_active
        or user.deleted_at is not None
        or not verify_password(password, user.password_hash)
    ):
        result = record_login_failure(db, key_hash)

        if result["is_locked"]:
            raise LoginThrottled

        raise InvalidCredentials

    clear_login_failures(db, key_hash)

    return user

def update_user_profile(
    db: DBSession,
    user: User,
    full_name: str,
    username: str,
) -> User:
    full_name = full_name.strip()
    username = normalize_username(username)

    if not full_name or len(full_name) > 150:
        raise ValueError(
            "Nama lengkap harus berisi 1–150 karakter."
        )

    if not re.fullmatch(r"[a-z0-9_]{3,50}", username):
        raise ValueError(
            "Username harus terdiri dari 3–50 karakter, "
            "hanya huruf kecil, angka, dan underscore."
        )

    existing_user = db.scalar(
        select(User).where(
            User.username == username,
            User.id != user.id,
        )
    )

    if existing_user:
        raise UsernameAlreadyExists

    user.full_name = full_name
    user.username = username

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise UsernameAlreadyExists

    return user


def change_user_password(
    db: DBSession,
    user: User,
    current_password: str,
    new_password: str,
) -> None:
    if not verify_password(current_password, user.password_hash):
        raise InvalidCredentials

    if len(new_password) < 6 or len(new_password) > 128:
        raise ValueError(
            "Password harus terdiri dari 6–128 karakter."
        )

    user.password_hash = hash_password(new_password)
    db.commit()
