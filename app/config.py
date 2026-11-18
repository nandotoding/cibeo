
import os

from dotenv import load_dotenv

load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
DIRECT_URL = os.getenv("DIRECT_URL")

SECRET_KEY = os.getenv("SECRET_KEY")
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()

if APP_ENV not in {"development", "production"}:
    raise RuntimeError(
        "APP_ENV must be either 'development' or 'production'."
    )
