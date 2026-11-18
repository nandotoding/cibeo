import hmac
import uuid
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DBSession

from app.config import APP_ENV
from app.database import get_db
from app.models.auth import (
    User,
    AdminAccount,
    utc_now,
)
from app.models.finance import (
    IncomeTransaction,
    ExpenseTransaction,
)
from app.services.auth import (
    create_session,
    delete_session,
    delete_all_sessions,
)
from app.services.csrf import (
    generate_pre_auth_csrf_token,
    verify_pre_auth_csrf_token,
)
from app.services.dependencies import (
    SESSION_COOKIE_NAME,
    get_current_session,
    get_current_admin,
    require_admin_page,
)
from app.services.admin_auth import (
    authenticate_admin,
    InvalidAdminCredentials,
    AdminLoginThrottled,
)
from app.services.admin_setup import ensure_admin_account
from app.services.security import hash_token, hash_password


router = APIRouter(prefix="/admin", tags=["Admin"])

CSRF_COOKIE_NAME = "cibeo_csrf"
COOKIE_SECURE = APP_ENV == "production"

BASE_DIR = Path(__file__).resolve().parent.parent

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


def wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept.lower()


def render_admin_login(
    request: Request,
    error: str | None = None,
    success: str | None = None,
):
    token = generate_pre_auth_csrf_token()

    response = templates.TemplateResponse(
        request=request,
        name="admin/login.html",
        context={
            "csrf_token": token,
            "error": error,
            "success": success,
        },
    )

    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=7200,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return response


@router.get("/login")
def admin_login_page(request: Request):
    success = None

    if request.query_params.get("logged_out") == "1":
        success = "You have signed out successfully."

    return render_admin_login(
        request=request,
        success=success,
    )


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
        message = "Too many login attempts. Try again later."

        if wants_html(request):
            return render_admin_login(
                request=request,
                error=message,
            )

        raise HTTPException(
            status_code=429,
            detail=message,
        )

    except InvalidAdminCredentials:
        if wants_html(request):
            return render_admin_login(
                request=request,
                error="Invalid username or password.",
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    session_token, csrf_session_token = create_session(
        db,
        "admin",
        admin.id,
    )

    if wants_html(request):
        login_response = RedirectResponse(
            url="/admin",
            status_code=303,
        )
    else:
        login_response = response

    login_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=12 * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    login_response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_session_token,
        max_age=12 * 60 * 60,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    if wants_html(request):
        return login_response

    return {
        "message": "Admin login successful",
        "username": admin.username,
    }


@router.post("/logout")
def admin_logout(
    request: Request,
    response: Response,
    csrf_token: str | None = Form(default=None),
    current_session=Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

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
            url="/admin/login?logged_out=1",
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

    return {"message": "Admin logout successful"}


@router.get("/me")
def admin_me(
    admin=Depends(get_current_admin),
):
    return {
        "username": admin.username,
        "role": "admin",
    }


@router.get("")
def admin_dashboard(
    request: Request,
    admin=Depends(require_admin_page),
    db: DBSession = Depends(get_db),
):
    registered_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.deleted_at.is_(None))
    ) or 0

    active_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.is_active.is_(True),
            User.deleted_at.is_(None),
        )
    ) or 0

    inactive_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.is_active.is_(False),
            User.deleted_at.is_(None),
        )
    ) or 0

    deleted_users = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.deleted_at.is_not(None))
    ) or 0

    return templates.TemplateResponse(
        request=request,
        name="admin/dashboard.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "dashboard",
            "registered_users": registered_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "deleted_users": deleted_users,
        },
    )


@router.get("/users")
def admin_user_list(
    request: Request,
    admin=Depends(require_admin_page),
    db: DBSession = Depends(get_db),
):
    users = db.scalars(
        select(User)
        .where(User.deleted_at.is_(None))
        .order_by(User.created_at.desc())
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="admin/users/index.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "users",
            "users": users,
        },
    )


@router.get("/users/{user_id}")
def admin_user_detail(
    request: Request,
    user_id: uuid.UUID,
    admin=Depends(require_admin_page),
    db: DBSession = Depends(get_db),
):
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    income_summary = db.execute(
        select(
            func.count(IncomeTransaction.id),
            func.coalesce(
                func.sum(IncomeTransaction.amount),
                0,
            ),
        ).where(
            IncomeTransaction.user_id == user.id
        )
    ).one()

    expense_summary = db.execute(
        select(
            func.count(ExpenseTransaction.id),
            func.coalesce(
                func.sum(ExpenseTransaction.amount),
                0,
            ),
        ).where(
            ExpenseTransaction.user_id == user.id
        )
    ).one()

    return templates.TemplateResponse(
        request=request,
        name="admin/users/detail.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "users",
            "user": user,
            "income_count": income_summary[0],
            "income_total": income_summary[1],
            "expense_count": expense_summary[0],
            "expense_total": expense_summary[1],
        },
    )


@router.post("/users/{user_id}/status")
def admin_update_user_status(
    request: Request,
    user_id: uuid.UUID,
    action: str = Form(...),
    csrf_token: str = Form(...),
    admin=Depends(get_current_admin),
    current_session=Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    # Validate CSRF token
    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    # Find user
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    # Deactivate user
    if action == "deactivate":
        if user.is_active:
            delete_all_sessions(db, "user", user.id)
            user.is_active = False
            db.commit()

    # Reactivate user
    elif action == "reactivate":
        if not user.is_active:
            user.is_active = True
            db.commit()

    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid account action",
        )

    return RedirectResponse(
        url=f"/admin/users/{user.id}",
        status_code=303,
    )


@router.post("/users/{user_id}/password")
def admin_reset_user_password(
    request: Request,
    user_id: uuid.UUID,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    admin=Depends(get_current_admin),
    current_session=Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    # Validate CSRF token
    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    # Validate password
    if len(new_password) < 6 or len(new_password) > 128:
        raise HTTPException(
            status_code=400,
            detail="Password must be between 6 and 128 characters.",
        )

    if new_password != confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Password confirmation does not match.",
        )

    # Find user
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    # Update password and revoke all sessions
    user.password_hash = hash_password(new_password)
    db.commit()

    delete_all_sessions(db, "user", user.id)

    return RedirectResponse(
        url=f"/admin/users/{user.id}",
        status_code=303,
    )


@router.post("/users/{user_id}/delete")
def admin_soft_delete_user(
    request: Request,
    user_id: uuid.UUID,
    csrf_token: str = Form(...),
    admin=Depends(get_current_admin),
    current_session=Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    # Validate CSRF token
    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    # Find user
    user = db.scalar(
        select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
        )
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    # Soft delete and deactivate user
    user.deleted_at = utc_now()
    user.is_active = False
    db.commit()

    # Revoke all user sessions
    delete_all_sessions(db, "user", user.id)

    return RedirectResponse(
        url="/admin/users",
        status_code=303,
    )


@router.get("/administrators")
def admin_administrator_list(
    request: Request,
    admin=Depends(require_admin_page),
    db: DBSession = Depends(get_db),
):
    administrators = db.scalars(
        select(AdminAccount).order_by(
            AdminAccount.created_at.desc()
        )
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="admin/administrators/index.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "administrators",
            "administrators": administrators,
        },
    )


@router.post("/administrators/create")
def admin_create_administrator(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    admin=Depends(get_current_admin),
    current_session=Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    # Validate CSRF token
    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    # Validate password confirmation
    if password != confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Password confirmation does not match.",
        )

    # Create administrator account
    try:
        created = ensure_admin_account(
            db=db,
            username=username,
            password=password,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if not created:
        raise HTTPException(
            status_code=409,
            detail="Username is already registered.",
        )

    return RedirectResponse(
        url="/admin/administrators",
        status_code=303,
    )


@router.get("/administrators/create")
def admin_create_administrator_page(
    request: Request,
    admin=Depends(require_admin_page),
):
    return templates.TemplateResponse(
        request=request,
        name="admin/administrators/create.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "administrators",
        },
    )


@router.get("/administrators/{admin_id}")
def admin_administrator_detail(
    request: Request,
    admin_id: uuid.UUID,
    admin=Depends(require_admin_page),
    db: DBSession = Depends(get_db),
):
    administrator = db.scalar(
        select(AdminAccount).where(
            AdminAccount.id == admin_id
        )
    )

    if administrator is None:
        raise HTTPException(
            status_code=404,
            detail="Administrator not found",
        )

    return templates.TemplateResponse(
        request=request,
        name="admin/administrators/detail.html",
        context={
            "admin": admin,
            "csrf_token": request.cookies.get(CSRF_COOKIE_NAME),
            "active_page": "administrators",
            "administrator": administrator,
        },
    )
