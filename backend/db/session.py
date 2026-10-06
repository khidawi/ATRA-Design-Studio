"""
Database engine and session factory (Task 1 — persistence foundation).

PostgreSQL via SQLAlchemy 2.x and psycopg 3. Everything that has to survive
a restart (organisation, later: regulations, rules, designs, contracts) goes
through this module; the scoring engine in backend/framework/ stays pure and
never touches the database.
"""
import os
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://stai:stai@localhost:5432/stai"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    with SessionLocal() as session:
        yield session
