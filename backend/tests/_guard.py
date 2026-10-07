"""
The API and end-to-end suites create data and then clear whole tables (every drift item, finding and pack), because they assert
exact counts. Run against a database someone is really using, that destroys their work. So they refuse to start unless the database
is clearly a scratch one, or you say so explicitly.

    docker compose exec -e ASTRA_TESTS_ON_THIS_DB=1 backend python -m tests.test_overview     # you accept that the data here may be deleted
"""
import os
import sys

from db.session import DATABASE_URL


def require_scratch_database() -> None:
    name = DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
    if os.environ.get("ASTRA_TESTS_ON_THIS_DB") == "1" or name.endswith("_test") or name.endswith("-test"):
        return
    sys.exit(f"Refusing to run: these tests delete data (drift items, findings, packs, agents they created) and the database '{name}' may hold real work.\n"
             "Use a scratch database (a name ending in _test), or set ASTRA_TESTS_ON_THIS_DB=1 to accept that the data may be deleted.")
