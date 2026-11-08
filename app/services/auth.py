import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, delete
from sqlalchemy.orm import Session as DBSession

from app.models.auth import Session
from app.services.security import (
    generate_session_token,
    generate_csrf_token,
    hash_token,
)


SESSION_DURATION_HOURS = 12


def create_session(
    db: DBSession,
    subject_type: str,
    subject_id: uuid.UUID,
):
    if subject_type not in ("user", "admin"):
        raise ValueError("Invalid subject type")

    session_token = generate_session_token()
    csrf_token = generate_csrf_token()

    session = Session(
        token_hash=hash_token(session_token),
        csrf_token_hash=hash_token(csrf_token),
        subject_type=subject_type,
        subject_id=subject_id,
        expires_at=datetime.now(timezone.utc)
        + timedelta(hours=SESSION_DURATION_HOURS),
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return session_token, csrf_token


def get_valid_session(
    db: DBSession,
    session_token: str,
):
    if not session_token:
        return None

    token_hash = hash_token(session_token)

    statement = select(Session).where(
        Session.token_hash == token_hash,
        Session.expires_at > datetime.now(timezone.utc),
    )

    return db.scalar(statement)


def delete_session(
    db: DBSession,
    session_token: str,
):
    if not session_token:
        return

    statement = delete(Session).where(
        Session.token_hash == hash_token(session_token)
    )

    db.execute(statement)
    db.commit()


def delete_all_sessions(
    db: DBSession,
    subject_type: str,
    subject_id: uuid.UUID,
):
    statement = delete(Session).where(
        Session.subject_type == subject_type,
        Session.subject_id == subject_id,
    )

    db.execute(statement)
    db.commit()
