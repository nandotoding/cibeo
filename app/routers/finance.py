import hmac
from uuid import UUID
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from app.database import SessionLocal, get_db
from app.models.auth import User, Session as AuthSession
from app.models.finance import (
    ExpenseTransaction,
    IncomeTransaction,
)
from app.services.auth import get_valid_session
from app.services.dependencies import get_current_session
from app.services.finance import (
    create_standard_version,
    get_current_month,
    get_standard_for_month,
    get_standard_history,
    get_standard_items,
)
from app.services.security import hash_token


router = APIRouter(tags=["Finance"])

BASE_DIR = Path(__file__).resolve().parent.parent
APP_TIMEZONE = ZoneInfo("Asia/Jakarta")

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


def get_authenticated_user(request: Request, db: DBSession):
    session_token = request.cookies.get("cibeo_session")

    if not session_token:
        return None, RedirectResponse(
            url="/login",
            status_code=303,
        )

    auth_session = get_valid_session(db, session_token)

    if not auth_session:
        return None, RedirectResponse(
            url="/login",
            status_code=303,
        )

    if auth_session.subject_type == "admin":
        return None, RedirectResponse(
            url="/admin",
            status_code=303,
        )

    if auth_session.subject_type != "user":
        return None, RedirectResponse(
            url="/login",
            status_code=303,
        )

    user = db.get(User, auth_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        return None, RedirectResponse(
            url="/login",
            status_code=303,
        )

    return user, None


@router.get("/management")
def management(request: Request):
    with SessionLocal() as db:
        user, redirect = get_authenticated_user(request, db)

        if redirect:
            return redirect

        current_month = get_current_month()

        standard = get_standard_for_month(
            db=db,
            user_id=user.id,
            target_month=current_month,
        )

        standard_items = (
            get_standard_items(db=db, version_id=standard.id)
            if standard else []
        )

        total_standard = sum(
            item.amount for item in standard_items
        )

        income_statement = (
            select(IncomeTransaction)
            .where(
                IncomeTransaction.user_id == user.id,
                IncomeTransaction.period_month == current_month,
            )
            .order_by(IncomeTransaction.created_at.desc())
        )

        expense_statement = (
            select(ExpenseTransaction)
            .where(
                ExpenseTransaction.user_id == user.id,
                ExpenseTransaction.period_month == current_month,
            )
            .order_by(ExpenseTransaction.created_at.desc())
        )

        incomes = list(db.scalars(income_statement).all())
        expenses = list(db.scalars(expense_statement).all())

        csrf_token = request.cookies.get("cibeo_csrf", "")

        return templates.TemplateResponse(
            request=request,
            name="finance/index.html",
            context={
                "user": user,
                "csrf_token": csrf_token,
                "current_month": current_month,
                "standard": standard,
                "total_standard": total_standard,
                "incomes": incomes,
                "expenses": expenses,
            },
        )


@router.get("/management/standards")
def manage_standards(request: Request):
    with SessionLocal() as db:
        user, redirect = get_authenticated_user(request, db)

        if redirect:
            return redirect

        current_month = get_current_month()

        standard = get_standard_for_month(
            db=db,
            user_id=user.id,
            target_month=current_month,
        )

        items = (
            get_standard_items(db=db, version_id=standard.id)
            if standard else []
        )

        total_standard = sum(
            item.amount for item in items
        )

        history = get_standard_history(
            db=db,
            user_id=user.id,
        )

        history_entries = []

        for version in history:
            version_items = get_standard_items(
                db=db,
                version_id=version.id,
            )

            history_entries.append({
                "version": version,
                "items": version_items,
                "total": sum(
                    item.amount for item in version_items
                ),
                "created_at_local": version.created_at.astimezone(
                    APP_TIMEZONE
                ),
                "is_current": (
                    standard is not None
                    and version.id == standard.id
                ),
            })

        csrf_token = request.cookies.get("cibeo_csrf", "")

        return templates.TemplateResponse(
            request=request,
            name="finance/standards.html",
            context={
                "user": user,
                "csrf_token": csrf_token,
                "current_month": current_month,
                "standard": standard,
                "items": items,
                "total_standard": total_standard,
                "history_entries": history_entries,
            },
        )


@router.post("/management/standards")
def save_standard(
    description: list[str] = Form(...),
    category: list[str] = Form(...),
    amount: list[int] = Form(...),
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(
            status_code=403,
            detail="Access forbidden",
        )

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(
            status_code=403,
            detail="Inactive or invalid user",
        )

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    if not (
        len(description) == len(category) == len(amount)
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid standard items",
        )

    items = [
        {
            "description": desc,
            "category": cat,
            "amount": value,
        }
        for desc, cat, value in zip(
            description,
            category,
            amount,
        )
    ]

    try:
        create_standard_version(
            db=db,
            user_id=user.id,
            items=items,
        )
    except ValueError:
        return RedirectResponse(
            url="/management/standards?error=invalid_standard",
            status_code=303,
        )

    return RedirectResponse(
        url="/management/standards?saved=1",
        status_code=303,
    )


@router.post("/management/income")
def save_income(
    description: str = Form(...),
    category: str = Form(...),
    amount: int = Form(...),
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(
            status_code=403,
            detail="Access forbidden",
        )

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(
            status_code=403,
            detail="Inactive or invalid user",
        )

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    description = description.strip()

    if (
        not description
        or len(description) > 200
        or category not in {"fixed", "additional"}
        or amount <= 0
    ):
        return RedirectResponse(
            url="/management?error=invalid_income",
            status_code=303,
        )

    transaction = IncomeTransaction(
        user_id=user.id,
        period_month=get_current_month(),
        description=description,
        category=category,
        amount=amount,
    )

    try:
        db.add(transaction)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?income_saved=1",
        status_code=303,
    )


@router.post("/management/income/{transaction_id}/edit")
def edit_income(
    transaction_id: UUID,
    description: str = Form(...),
    category: str = Form(...),
    amount: int = Form(...),
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(status_code=403, detail="Access forbidden")

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(status_code=403, detail="Inactive or invalid user")

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    transaction = db.get(IncomeTransaction, transaction_id)

    if (
        not transaction
        or transaction.user_id != user.id
        or transaction.period_month != get_current_month()
    ):
        raise HTTPException(status_code=404, detail="Transaction not found")

    description = description.strip()

    if (
        not description
        or len(description) > 200
        or category not in {"fixed", "additional"}
        or amount <= 0
    ):
        return RedirectResponse(
            url="/management?error=invalid_income",
            status_code=303,
        )

    transaction.description = description
    transaction.category = category
    transaction.amount = amount

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?income_updated=1",
        status_code=303,
    )


@router.post("/management/income/{transaction_id}/delete")
def delete_income(
    transaction_id: UUID,
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(status_code=403, detail="Access forbidden")

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(status_code=403, detail="Inactive or invalid user")

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    transaction = db.get(IncomeTransaction, transaction_id)

    if (
        not transaction
        or transaction.user_id != user.id
        or transaction.period_month != get_current_month()
    ):
        raise HTTPException(status_code=404, detail="Transaction not found")

    try:
        db.delete(transaction)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?income_deleted=1",
        status_code=303,
    )


@router.post("/management/expense/{transaction_id}/edit")
def edit_expense(
    transaction_id: UUID,
    description: str = Form(...),
    category: str = Form(...),
    amount: int = Form(...),
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(status_code=403, detail="Access forbidden")

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(status_code=403, detail="Inactive or invalid user")

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    transaction = db.get(ExpenseTransaction, transaction_id)

    if (
        not transaction
        or transaction.user_id != user.id
        or transaction.period_month != get_current_month()
    ):
        raise HTTPException(status_code=404, detail="Transaction not found")

    description = description.strip()

    if (
        not description
        or len(description) > 200
        or category not in {"fixed", "additional"}
        or amount <= 0
    ):
        return RedirectResponse(
            url="/management?error=invalid_expense",
            status_code=303,
        )

    transaction.description = description
    transaction.category = category
    transaction.amount = amount

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?expense_updated=1",
        status_code=303,
    )


@router.post("/management/expense/{transaction_id}/delete")
def delete_expense(
    transaction_id: UUID,
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(status_code=403, detail="Access forbidden")

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(status_code=403, detail="Inactive or invalid user")

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    transaction = db.get(ExpenseTransaction, transaction_id)

    if (
        not transaction
        or transaction.user_id != user.id
        or transaction.period_month != get_current_month()
    ):
        raise HTTPException(status_code=404, detail="Transaction not found")

    try:
        db.delete(transaction)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?expense_deleted=1",
        status_code=303,
    )

@router.post("/management/expense")
def save_expense(
    description: str = Form(...),
    category: str = Form(...),
    amount: int = Form(...),
    csrf_token: str = Form(...),
    current_session: AuthSession = Depends(get_current_session),
    db: DBSession = Depends(get_db),
):
    if current_session.subject_type != "user":
        raise HTTPException(
            status_code=403,
            detail="Access forbidden",
        )

    user = db.get(User, current_session.subject_id)

    if (not user or not user.is_active or user.deleted_at is not None):
        raise HTTPException(
            status_code=403,
            detail="Inactive or invalid user",
        )

    if not hmac.compare_digest(
        hash_token(csrf_token),
        current_session.csrf_token_hash,
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )

    description = description.strip()

    if (
        not description
        or len(description) > 200
        or category not in {"fixed", "additional"}
        or amount <= 0
    ):
        return RedirectResponse(
            url="/management?error=invalid_expense",
            status_code=303,
        )

    transaction = ExpenseTransaction(
        user_id=user.id,
        period_month=get_current_month(),
        description=description,
        category=category,
        amount=amount,
    )

    try:
        db.add(transaction)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return RedirectResponse(
        url="/management?expense_saved=1",
        status_code=303,
    )
