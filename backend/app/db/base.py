"""
SQLAlchemy declarative base.
All ORM models must inherit from this Base so Alembic can detect them.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass
