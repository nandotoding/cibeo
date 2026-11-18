from datetime import date, datetime, timezone
from typing import Any, Sequence
from uuid import UUID
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finance import StandardItem, StandardVersion


VALID_CATEGORIES = {"fixed", "additional"}
APP_TIMEZONE = ZoneInfo("Asia/Jakarta")


def get_current_month() -> date:
    """
    Mengambil bulan berjalan berdasarkan waktu Jakarta.
    """
    today = datetime.now(APP_TIMEZONE).date()
    return date(today.year, today.month, 1)


def normalize_month(value: date) -> date:
    """
    Memastikan periode menggunakan tanggal pertama bulan.
    """
    if not isinstance(value, date):
        raise ValueError("Month must be a date.")

    return date(value.year, value.month, 1)


def validate_standard_items(
    items: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Memvalidasi seluruh komponen standar sebelum disimpan.
    """
    if not items:
        raise ValueError("At least one standard item is required.")

    validated_items = []

    for index, item in enumerate(items, start=1):
        description = item.get("description")
        category = item.get("category")
        amount = item.get("amount")

        if not isinstance(description, str):
            raise ValueError(
                f"Item {index}: description must be text."
            )

        description = description.strip()

        if not description or len(description) > 200:
            raise ValueError(
                f"Item {index}: description must contain 1–200 characters."
            )

        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Item {index}: category must be fixed or additional."
            )

        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError(
                f"Item {index}: amount must be an integer."
            )

        if amount < 0:
            raise ValueError(
                f"Item {index}: amount cannot be negative."
            )

        validated_items.append(
            {
                "description": description,
                "category": category,
                "amount": amount,
            }
        )

    return validated_items


def create_standard_version(
    db: Session,
    user_id: UUID,
    items: Sequence[dict[str, Any]],
) -> StandardVersion:
    """
    Membuat versi standar baru.

    Bulan efektif ditentukan otomatis berdasarkan bulan
    berjalan di zona waktu Asia/Jakarta.

    Versi sebelumnya tidak diubah.
    """
    effective_month = get_current_month()
    validated_items = validate_standard_items(items)

    version = StandardVersion(
        user_id=user_id,
        effective_from_month=effective_month,
        created_at=datetime.now(timezone.utc),
    )

    try:
        db.add(version)
        db.flush()

        for item in validated_items:
            db.add(
                StandardItem(
                    version_id=version.id,
                    description=item["description"],
                    category=item["category"],
                    amount=item["amount"],
                )
            )

        db.commit()
        db.refresh(version)

        return version

    except Exception:
        db.rollback()
        raise


def get_standard_for_month(
    db: Session,
    user_id: UUID,
    target_month: date,
) -> StandardVersion | None:
    """
    Mengambil versi standar terakhir yang berlaku
    pada bulan yang diminta.
    """
    target = normalize_month(target_month)

    statement = (
        select(StandardVersion)
        .where(
            StandardVersion.user_id == user_id,
            StandardVersion.effective_from_month <= target,
        )
        .order_by(
            StandardVersion.effective_from_month.desc(),
            StandardVersion.created_at.desc(),
            StandardVersion.id.desc(),
        )
        .limit(1)
    )

    return db.scalar(statement)


def get_standard_items(
    db: Session,
    version_id: UUID,
) -> list[StandardItem]:
    """
    Mengambil seluruh komponen dari satu versi standar.
    """
    statement = (
        select(StandardItem)
        .where(StandardItem.version_id == version_id)
        .order_by(StandardItem.description.asc())
    )

    return list(db.scalars(statement).all())


def get_standard_history(
    db: Session,
    user_id: UUID,
) -> list[StandardVersion]:
    """
    Mengambil riwayat perubahan standar milik pengguna.
    """
    statement = (
        select(StandardVersion)
        .where(StandardVersion.user_id == user_id)
        .order_by(
            StandardVersion.effective_from_month.desc(),
            StandardVersion.created_at.desc(),
            StandardVersion.id.desc(),
        )
    )

    return list(db.scalars(statement).all())