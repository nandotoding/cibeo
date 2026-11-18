import hmac

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models.auth import User
from app.services.auth import delete_all_sessions
from app.services.dependencies import (
    SESSION_COOKIE_NAME,
    get_current_session,
    get_current_user,
)
from app.services.security import hash_token
from app.services.user_auth import (
    UsernameAlreadyExists,
    InvalidCredentials,
    update_user_profile,
    change_user_password,
)


router = APIRouter(tags=["Profile"])
templates = Jinja2Templates(directory="app/templates")


def validate_csrf_token(
    submitted_token: str,
    csrf_token_hash: str,
) -> None:
    if not submitted_token:
        raise HTTPException(
            status_code=403,
            detail="CSRF token required",
        )

    if not hmac.compare_digest(
        hash_token(submitted_token),
        csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )


@router.get("/profile", response_class=HTMLResponse)
def profile_page(
    request: Request,
    current_session=Depends(get_current_session),
    user: User = Depends(get_current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="profile/index.html",
        context={
            "user": user,
            "csrf_token": request.cookies.get("cibeo_csrf", ""),
        },
    )


@router.post("/profile/update")
def update_profile(
    full_name: str = Form(...),
    username: str = Form(...),
    csrf_token: str = Form(...),
    current_session=Depends(get_current_session),
    user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    validate_csrf_token(
        csrf_token,
        current_session.csrf_token_hash,
    )

    try:
        update_user_profile(
            db=db,
            user=user,
            full_name=full_name,
            username=username,
        )
    except UsernameAlreadyExists:
        return RedirectResponse(
            url="/profile?profile_error=username_taken",
            status_code=303,
        )
    except ValueError:
        return RedirectResponse(
            url="/profile?profile_error=invalid_input",
            status_code=303,
        )

    return RedirectResponse(
        url="/profile?profile_updated=1",
        status_code=303,
    )


@router.post("/profile/password")
def update_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    current_session=Depends(get_current_session),
    user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    validate_csrf_token(
        csrf_token,
        current_session.csrf_token_hash,
    )

    if new_password != confirm_password:
        return RedirectResponse(
            url="/profile?password_error=password_mismatch",
            status_code=303,
        )

    try:
        change_user_password(
            db=db,
            user=user,
            current_password=current_password,
            new_password=new_password,
        )
    except InvalidCredentials:
        return RedirectResponse(
            url="/profile?password_error=incorrect_current",
            status_code=303,
        )
    except ValueError:
        return RedirectResponse(
            url="/profile?password_error=invalid_password",
            status_code=303,
        )

    delete_all_sessions(
        db=db,
        subject_type="user",
        subject_id=user.id,
    )

    response = RedirectResponse(
        url="/login?password_changed=1",
        status_code=303,
    )
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie("cibeo_csrf", path="/")

    return response