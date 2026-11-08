
from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
)
from sqlalchemy.orm import Session as DBSession

from app.config import APP_ENV
from app.database import get_db
from app.services.auth import create_session, delete_session
from app.services.csrf import (
    generate_pre_auth_csrf_token,
    verify_pre_auth_csrf_token,
)
from app.services.dependencies import (
    SESSION_COOKIE_NAME,
    get_current_session,
    get_current_admin,
    verify_csrf,
)
from app.services.admin_auth import (
    authenticate_admin,
    InvalidAdminCredentials,
    AdminLoginThrottled,
)


router = APIRouter(prefix="/admin", tags=["Admin"])

CSRF_COOKIE_NAME = "cibeo_csrf"
COOKIE_SECURE = APP_ENV == "production"


@router.get("/csrf")
def get_admin_csrf_token(response: Response):
    token = generate_pre_auth_csrf_token()

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=7200,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {"csrf_token": token}


@router.post("/login")
def admin_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: DBSession = Depends(get_db),
):
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not verify_pre_auth_csrf_token(
        cookie_token,
        csrf_token,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    try:
        admin = authenticate_admin(
            db,
            username,
            password,
            client_ip,
        )
    except AdminLoginThrottled:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
        )
    except InvalidAdminCredentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    session_token, csrf_session_token = create_session(
        db,
        "admin",
        admin.id,
    )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=12 * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_session_token,
        max_age=12 * 60 * 60,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {
        "message": "Admin login successful",
        "username": admin.username,
    }


@router.post("/logout")
def admin_logout(
    request: Request,
    response: Response,
    current_session=Depends(get_current_session),
    _: None = Depends(verify_csrf),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    delete_session(db, session_token)

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )

    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        httponly=False,
        samesite="lax",
    )

    return {"message": "Admin logout successful"}


@router.get("/me")
def admin_me(
    admin=Depends(get_current_admin),
):
    return {
        "username": admin.username,
        "role": "admin",
    }

