from pathlib import Path
from fastapi.templating import Jinja2Templates
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from sqlalchemy.orm import Session as DBSession
from fastapi.responses import RedirectResponse
import hmac

from app.config import APP_ENV
from app.database import get_db
from app.models.auth import Session as AuthSession
from app.services.auth import (
    SESSION_DURATION_HOURS,
    create_session,
    delete_session,
)
from app.services.csrf import (
    generate_pre_auth_csrf_token,
    verify_pre_auth_csrf_token,
)
from app.services.dependencies import (
    SESSION_COOKIE_NAME,
    get_current_session,
    verify_csrf,
)
from app.services.login_throttle import (
    make_login_key,
    clear_login_failures,
)
from app.services.user_auth import (
    register_user,
    authenticate_user,
    UsernameAlreadyExists,
    InvalidCredentials,
    LoginThrottled,
)
from app.services.security import hash_token


router = APIRouter()

CSRF_COOKIE_NAME = "cibeo_csrf"
PRE_AUTH_CSRF_MAX_AGE = 7200

COOKIE_SECURE = APP_ENV == "production"

BASE_DIR = Path(__file__).resolve().parent.parent

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)

def wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept.lower()


def render_auth_page(
    request: Request,
    page: str,
    error: str | None = None,
    success: str | None = None,
):
    token = generate_pre_auth_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name=f"auth/{page}.html",
        context={
            "csrf_token": token,
            "error": error,
            "success": success,
        },
    )

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=PRE_AUTH_CSRF_MAX_AGE,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return response


@router.get("/login")
def login_page(request: Request):
    success = None

    if request.query_params.get("registered") == "1":
        success = "Registration successful. Please sign in."
    elif request.query_params.get("logged_out") == "1":
        success = "You have signed out successfully."

    return render_auth_page(
        request,
        "login",
        success=success,
    )

@router.get("/signup")
def signup_page(request: Request, response: Response):
    token = generate_pre_auth_csrf_token()

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=PRE_AUTH_CSRF_MAX_AGE,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return templates.TemplateResponse(
        request=request,
        name="auth/signup.html",
        context={
            "csrf_token": token,
        },
    )

@router.get("/auth/csrf")
def get_csrf_token(response: Response):
    """
    Mengeluarkan token CSRF sementara sebelum login/signup.
    """
    token = generate_pre_auth_csrf_token()

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=PRE_AUTH_CSRF_MAX_AGE,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {"csrf_token": token}


def validate_pre_auth_csrf(
    request: Request,
    submitted_token: str,
):
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not verify_pre_auth_csrf_token(
        cookie_token,
        submitted_token,
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed",
        )


@router.post("/signup", status_code=201)
def signup(
    request: Request,
    response: Response,
    full_name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: DBSession = Depends(get_db),
):
    validate_pre_auth_csrf(request, csrf_token)

    try:
        user = register_user(
            db=db,
            full_name=full_name,
            username=username,
            password=password,
        )

    except UsernameAlreadyExists:
        if wants_html(request):
            return render_auth_page(
                request,
                "signup",
                error="Username already exists.",
            )

        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    except ValueError as exc:
        if wants_html(request):
            return render_auth_page(
                request,
                "signup",
                error=str(exc),
            )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    if wants_html(request):
        return RedirectResponse(
            url="/login?registered=1",
            status_code=303,
        )

    return {
        "message": "Registration successful",
        "username": user.username,
    }


@router.post("/login")
def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: DBSession = Depends(get_db),
):
    validate_pre_auth_csrf(request, csrf_token)

    client_ip = (
        request.client.host
        if request.client is not None
        else "unknown"
    )

    try:
        user = authenticate_user(
            db=db,
            username=username,
            password=password,
            ip_address=client_ip,
        )

    except LoginThrottled:
        message = "Too many failed login attempts. Try again later."

        if wants_html(request):
            return render_auth_page(
                request,
                "login",
                error=message,
            )

        raise HTTPException(
            status_code=429,
            detail=message,
        )

    except InvalidCredentials:
        if wants_html(request):
            return render_auth_page(
                request,
                "login",
                error="Invalid username or password.",
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    session_token, csrf_session_token = create_session(
        db=db,
        subject_type="user",
        subject_id=user.id,
    )

    session_max_age = SESSION_DURATION_HOURS * 60 * 60

    if wants_html(request):
        login_response = RedirectResponse(
            url="/dashboard",
            status_code=303,
        )
    else:
        login_response = response

    login_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=session_max_age,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    login_response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_session_token,
        max_age=session_max_age,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    if wants_html(request):
        return login_response

    return {
        "message": "Login successful",
        "username": user.username,
        "full_name": user.full_name,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    csrf_token: str | None = Form(default=None),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    # Only regular user sessions can use this endpoint.
    if current_session.subject_type != "user":
        raise HTTPException(
            status_code=403,
            detail="Access forbidden",
        )

    # Accept CSRF token from either HTML form or API header.
    submitted_token = (
        csrf_token
        or request.headers.get("X-CSRF-Token")
    )

    if (
        not submitted_token
        or not hmac.compare_digest(
            hash_token(submitted_token),
            current_session.csrf_token_hash,
        )
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    delete_session(db, session_token)

    if wants_html(request):
        logout_response = RedirectResponse(
            url="/login?logged_out=1",
            status_code=303,
        )
    else:
        logout_response = response

    logout_response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )

    logout_response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=COOKIE_SECURE,
        httponly=False,
        samesite="lax",
    )

    if wants_html(request):
        return logout_response

    return {"message": "Logout successful"}
