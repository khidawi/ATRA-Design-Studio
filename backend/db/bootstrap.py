"""
Start-up: wait for PostgreSQL, apply migrations, make sure the default
organisation exists. Safe to run on every start.
"""
import logging
import os
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select, text

from db.models import Organisation
from db.seed import ensure_reference_data
from db.seed_rcr import ensure_rcr_profiles
from db.session import SessionLocal, engine

log = logging.getLogger("stai.db")

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_ORG_SLUG = "default"
DEFAULT_ORG_NAME = os.environ.get("DEFAULT_ORG_NAME", "My organisation")


def wait_for_database(attempts: int = 30, delay: float = 1.0) -> None:
    last_error = None
    for _ in range(attempts):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # the database container may still be starting
            last_error = exc
            time.sleep(delay)
    raise RuntimeError(f"PostgreSQL is not reachable after {attempts}s: {last_error}")


def run_migrations() -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    command.upgrade(cfg, "head")


def ensure_default_organisation() -> None:
    with SessionLocal() as session:
        if session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG)) is None:
            session.add(Organisation(slug=DEFAULT_ORG_SLUG, name=DEFAULT_ORG_NAME))
            session.commit()
            log.info("Created default organisation %r", DEFAULT_ORG_NAME)


def init_database() -> None:
    wait_for_database()
    run_migrations()
    ensure_default_organisation()
    with SessionLocal() as session:
        ensure_reference_data(session)
        ensure_rcr_profiles(session)
