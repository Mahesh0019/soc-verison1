from datetime import datetime
from typing import Any

from sqlalchemy import or_


def paginate(query, page: int, page_size: int) -> tuple[list[Any], int]:
    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return items, total


def apply_keyword_search(query, model, q: str | None, fields: list[str]):
    if not q:
        return query
    clauses = [getattr(model, field).ilike(f"%{q}%") for field in fields]
    return query.filter(or_(*clauses))


def apply_date_range(query, column, date_from: datetime | None, date_to: datetime | None):
    if date_from:
        query = query.filter(column >= date_from)
    if date_to:
        query = query.filter(column <= date_to)
    return query


def apply_sort(query, model, sort_by: str | None, sort_order: str, allowed: set[str], default: str):
    field = sort_by if sort_by in allowed else default
    column = getattr(model, field)
    return query.order_by(column.asc() if sort_order == "asc" else column.desc())

