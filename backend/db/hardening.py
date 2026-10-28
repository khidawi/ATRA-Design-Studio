"""
Database privileges for the running application, applied at every start-up after the migrations.

The application connects as a role that can read and write data and nothing else. The tables belong to a different role that migrations use. So a flaw in the
application (an injection, a stolen session) cannot create, alter or drop a table, cannot take a lock on the schema, and cannot rewrite history:

  * data: SELECT, INSERT, UPDATE and DELETE on every table, and use of every sequence;
  * the audit log: INSERT and SELECT only. The log is a hash chain that claims to be append-only; with no UPDATE, DELETE or TRUNCATE for the application's role,
    the database enforces it, not just the code;
  * nothing else: no CREATE on the schema, no ownership, no superuser.

It runs as the owner role (DATABASE_URL_MIGRATE) and does nothing unless that is set and different from DATABASE_URL. It never creates the application's role (that
needs a password and is done once, by deploy/db/10-roles.sh when the database is first created); if the role is not there it says so and leaves things as they are.
"""
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

log = logging.getLogger("stai.db")

APPEND_ONLY = ("audit_events",)


def harden(owner_url: str, app_url: str) -> None:
    app_role = make_url(app_url).username
    owner_role = make_url(owner_url).username
    if not app_role or app_role == owner_role:
        return
    eng = create_engine(owner_url, pool_pre_ping=True)
    try:
        with eng.begin() as c:
            if c.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": app_role}).scalar() is None:
                log.warning("The database role %r does not exist, so its privileges were not set. Create it (deploy/db/10-roles.sh does) and restart.", app_role)
                return
            q = f'"{app_role}"'
            c.execute(text(f"GRANT USAGE ON SCHEMA public TO {q}"))
            c.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {q}"))
            c.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {q}"))
            c.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{owner_role}\" IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {q}"))
            c.execute(text(f"ALTER DEFAULT PRIVILEGES FOR ROLE \"{owner_role}\" IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {q}"))
            for t in APPEND_ONLY:
                if c.execute(text("SELECT to_regclass(:t)"), {"t": f"public.{t}"}).scalar() is not None:
                    c.execute(text(f'REVOKE UPDATE, DELETE, TRUNCATE ON "{t}" FROM {q}'))
        log.info("Database privileges set for %r: data only, and the audit log is append-only", app_role)
    finally:
        eng.dispose()
