from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.database import SessionLocal
from app.models.auth import User
from app.services.auth import get_valid_session

router = APIRouter(tags=["Dashboard"])

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/dashboard")
def dashboard(request: Request):
    session_token = request.cookies.get("cibeo_session")

    if not session_token:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    with SessionLocal() as db:
        auth_session = get_valid_session(db, session_token)

        if not auth_session:
            return RedirectResponse(
                url="/login",
                status_code=303,
            )

        if auth_session.subject_type == "admin":
            return RedirectResponse(
                url="/admin",
                status_code=303,
            )

        if auth_session.subject_type != "user":
            return RedirectResponse(
                url="/login",
                status_code=303,
            )

        user = db.get(User, auth_session.subject_id)

        if not user or not user.is_active:
            return RedirectResponse(
                url="/login",
                status_code=303,
            )

        csrf_token = request.cookies.get("cibeo_csrf", "")

        return templates.TemplateResponse(
            request=request,
            name="dashboard/index.html",
            context={
                "user": user,
                "csrf_token": csrf_token,
            },
        )
