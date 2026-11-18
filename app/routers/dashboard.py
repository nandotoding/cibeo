from datetime import date
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select

from app.database import SessionLocal
from app.models.auth import User
from app.models.finance import (
    ExpenseTransaction,
    IncomeTransaction,
)
from app.services.auth import get_valid_session
from app.services.finance import (
    get_current_month,
    get_standard_for_month,
    get_standard_items,
)

router = APIRouter(tags=["Dashboard"])

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def parse_selected_month(month_param: str | None) -> date:
    """
    Parse selected month in YYYY-MM format.
    Defaults to the current month in Asia/Jakarta.
    """
    if not month_param:
        return get_current_month()

    try:
        selected_month = date.fromisoformat(
            f"{month_param}-01"
        )

        if selected_month.strftime("%Y-%m") != month_param:
            raise ValueError

        return selected_month

    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Invalid month format. Use YYYY-MM.",
        )


@router.get("/dashboard")
def dashboard(request: Request):
    session_token = request.cookies.get("cibeo_session")

    if not session_token:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    selected_month = parse_selected_month(
        request.query_params.get("month")
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

        if (
            not user
            or not user.is_active
            or user.deleted_at is not None
        ):
            return RedirectResponse(
                url="/login",
                status_code=303,
            )

        csrf_token = request.cookies.get("cibeo_csrf", "")

                # All-time statistics, capped at the selected month
        current_month = get_current_month()

        cutoff_month = min(
            selected_month,
            current_month,
        )

        all_time_income = db.scalar(
            select(
                func.coalesce(
                    func.sum(IncomeTransaction.amount), 0
                )
            ).where(
                IncomeTransaction.user_id == user.id,
                IncomeTransaction.period_month <= cutoff_month,
            )
        )

        all_time_expenses = db.scalar(
            select(
                func.coalesce(
                    func.sum(ExpenseTransaction.amount), 0
                )
            ).where(
                ExpenseTransaction.user_id == user.id,
                ExpenseTransaction.period_month <= cutoff_month,
            )
        )

        all_time_income = int(all_time_income)
        all_time_expenses = int(all_time_expenses)

        # Income statistics
        income_stats = db.execute(
            select(
                func.coalesce(
                    func.sum(IncomeTransaction.amount), 0
                ).label("total_income"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                IncomeTransaction.category == "fixed",
                                IncomeTransaction.amount,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("fixed_income"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                IncomeTransaction.category == "additional",
                                IncomeTransaction.amount,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("additional_income"),
            ).where(
                IncomeTransaction.user_id == user.id,
                IncomeTransaction.period_month == selected_month,
            )
        ).one()

        # Expense statistics
        expense_stats = db.execute(
            select(
                func.coalesce(
                    func.sum(ExpenseTransaction.amount), 0
                ).label("total_expenses"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                ExpenseTransaction.category == "fixed",
                                ExpenseTransaction.amount,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("fixed_expenses"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                ExpenseTransaction.category == "additional",
                                ExpenseTransaction.amount,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("additional_expenses"),
            ).where(
                ExpenseTransaction.user_id == user.id,
                ExpenseTransaction.period_month == selected_month,
            )
        ).one()

        total_income = int(income_stats.total_income)
        fixed_income = int(income_stats.fixed_income)
        additional_income = int(income_stats.additional_income)

        total_expenses = int(expense_stats.total_expenses)
        fixed_expenses = int(expense_stats.fixed_expenses)
        additional_expenses = int(expense_stats.additional_expenses)

        # Financial balances
        surplus_deficit = total_income - total_expenses

        fixed_income_balance = (
            fixed_income - fixed_expenses
        )

        remaining_fixed_income = (
            fixed_income - total_expenses
        )

        # Expense standard applicable to selected month
        standard = get_standard_for_month(
            db,
            user.id,
            selected_month,
        )

        standard_items = (
            get_standard_items(db, standard.id)
            if standard
            else []
        )

        total_standard = sum(
            item.amount for item in standard_items
        )

        # Expense breakdown grouped by transaction description
        expense_breakdown_rows = db.execute(
            select(
                ExpenseTransaction.description,
                func.sum(ExpenseTransaction.amount).label("amount"),
            )
            .where(
                ExpenseTransaction.user_id == user.id,
                ExpenseTransaction.period_month == selected_month,
            )
            .group_by(ExpenseTransaction.description)
            .order_by(
                func.sum(ExpenseTransaction.amount).desc(),
                ExpenseTransaction.description.asc(),
            )
        ).all()

        expense_breakdown = [
            {
                "description": row.description,
                "amount": int(row.amount),
            }
            for row in expense_breakdown_rows
        ]

        return templates.TemplateResponse(
            request=request,
            name="dashboard/index.html",
            context={
                "user": user,
                "csrf_token": csrf_token,

                # Selected month
                "current_month": get_current_month(),
                "selected_month": selected_month,

                # Total statistics
                "total_income": total_income,
                "total_expenses": total_expenses,
                "all_time_income": all_time_income,
                "all_time_expenses": all_time_expenses,
                "total_expense": total_expenses,

                # Income statistics
                "fixed_income": fixed_income,
                "additional_income": additional_income,

                # Expense statistics
                "fixed_expenses": fixed_expenses,
                "additional_expenses": additional_expenses,

                # Financial balances
                "surplus_deficit": surplus_deficit,
                "fixed_income_balance": fixed_income_balance,
                "remaining_fixed_income": remaining_fixed_income,
                "remaining_balance": surplus_deficit,

                # Expense standard
                "total_standard": total_standard,
                "standard": standard,
                "standard_items": standard_items,

                # Chart data
                "expense_breakdown": expense_breakdown,
            },
        )
