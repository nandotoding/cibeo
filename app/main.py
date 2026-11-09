from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from app.services.dependencies import get_current_session
from app.services.auth import get_valid_session
from app.config import APP_ENV
from app.database import SessionLocal

from app.routers.auth import router as auth_router
from app.routers.admin import router as admin_router
from app.routers.dashboard import router as dashboard_router


# Application directories
BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


# Initialize FastAPI
app = FastAPI(
    title="Cibeo",
    description="Personal Finance Management Application",
    version="0.1.0",
)


# Static files
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


# Authentication routes
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(dashboard_router)

# Home page

@app.get("/")
def home(request: Request):
    session_token = request.cookies.get("cibeo_session")

    if session_token:
        with SessionLocal() as db:
            auth_session = get_valid_session(db, session_token)

            if auth_session:
                if auth_session.subject_type == "user":
                    return RedirectResponse(
                        url="/dashboard",
                        status_code=303,
                    )

                if auth_session.subject_type == "admin":
                    return RedirectResponse(
                        url="/admin",
                        status_code=303,
                    )

    return RedirectResponse(
        url="/login",
        status_code=303,
    )

# Health check
@app.get("/health")
def health_check():
    return {"status": "healthy"}
