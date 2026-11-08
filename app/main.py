from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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
    return templates.TemplateResponse(
        request=request,
        name="base.html",
        context={},
    )


# Health check
@app.get("/health")
def health_check():
    return {"status": "healthy"}
