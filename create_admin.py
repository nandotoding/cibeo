
import os
import sys
from getpass import getpass

from app.database import SessionLocal
from app.services.admin_setup import ensure_admin_account


def main():
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not username:
        username = input("Admin username: ").strip()

    if not password:
        password = getpass("Admin password: ")

    db = SessionLocal()

    try:
        created = ensure_admin_account(
            db=db,
            username=username,
            password=password,
        )

        if created:
            print("Admin account created successfully.")
        else:
            print("Admin account already exists. Password unchanged.")

    except ValueError as error:
        print(f"Invalid configuration: {error}")
        sys.exit(1)

    finally:
        db.close()


if __name__ == "__main__":
    main()

