
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from app.models.auth import User
from app.services.dependencies import get_current_user

router = APIRouter(tags=["Dashboard"])

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/dashboard")
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
):
    csrf_token = request.cookies.get("cibeo_csrf", "")

    return templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "user": user,
            "csrf_token": csrf_token,
        },
    )

