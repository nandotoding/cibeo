import hmac

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models.auth import User, AdminAccount, Session
from app.services.auth import get_valid_session
from app.services.security import hash_token


SESSION_COOKIE_NAME = "cibeo_session"


def get_current_session(
    request: Request,
    db: DBSession = Depends(get_db),
) -> Session:
    token = request.cookies.get(SESSION_COOKIE_NAME)

    session = get_valid_session(db, token)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    return session


def get_current_user(
    current_session: Session = Depends(get_current_session),
    db: DBSession = Depends(get_db),
) -> User:
    if current_session.subject_type != "user":
        raise HTTPException(
            status_code=403,
            detail="User access required",
        )

    user = db.get(User, current_session.subject_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Account unavailable",
        )

    return user


def get_current_admin(
    current_session: Session = Depends(get_current_session),
    db: DBSession = Depends(get_db),
) -> AdminAccount:
    if current_session.subject_type != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    admin = db.get(AdminAccount, current_session.subject_id)

    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Administrator account unavailable",
        )

    return admin


def verify_csrf(
    request: Request,
    current_session: Session = Depends(get_current_session),
):
    csrf_token = request.headers.get("X-CSRF-Token")

    if not csrf_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token required",
        )

    submitted_hash = hash_token(csrf_token)

    if not hmac.compare_digest(
        submitted_hash,
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )
