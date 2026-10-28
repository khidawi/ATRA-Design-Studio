"""
Checks the database security of a running production stack (docker-compose.prod.yml), from inside the API's own container, as the role the application really uses:

    python verify_db.py                       # run in the deploy folder, where docker-compose.prod.yml is

It confirms that the connection is encrypted (TLS 1.2 or later), that an unencrypted connection is refused, that the application's role is not a superuser and cannot create, alter or drop
a table, that the audit log can only be added to (no update, delete or truncate), that the application still has the data access it needs, and that the tables belong to a different
role. It changes nothing (each attempt to do something forbidden runs in a transaction that is rolled back). Exit code 0 if every check passes, 1 otherwise. Standard library only.
"""
import json
import subprocess
import sys

PROBE = r'''
import json, os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
out = {}
url = os.environ["DATABASE_URL"]
def rows(c, sql):
    return c.execute(text(sql)).all()
eng = create_engine(url)
with eng.connect() as c:
    out["user"] = rows(c, "select current_user")[0][0]
    out["super"] = rows(c, "select rolsuper from pg_roles where rolname = current_user")[0][0]
    out["createrole"] = rows(c, "select rolcreaterole or rolcreatedb from pg_roles where rolname = current_user")[0][0]
    ssl = rows(c, "select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid()")[0]
    out["ssl"], out["tls"], out["cipher"] = bool(ssl[0]), ssl[1], ssl[2]
    out["can_select"] = rows(c, "select count(*) from organisations")[0][0] >= 0
    out["owner_of_tables"] = rows(c, "select tableowner from pg_tables where tablename = 'organisations'")[0][0]
    p = lambda t, priv: rows(c, f"select has_table_privilege(current_user, '{t}', '{priv}')")[0][0]
    out["audit"] = {k: p("audit_events", k) for k in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")}
    out["data"] = {k: p("company_nodes", k) for k in ("SELECT", "INSERT", "UPDATE", "DELETE")}
    out["schema_create"] = rows(c, "select has_schema_privilege(current_user, 'public', 'CREATE')")[0][0]
    def attempt(sql):
        # Every attempt runs in a transaction that is always rolled back: DDL and TRUNCATE are transactional in PostgreSQL, so even if a privilege were wrongly granted the probe
        # would change nothing.
        with eng.connect() as c2:
            t = c2.begin()
            try:
                c2.execute(text(sql))
                return "allowed"
            except Exception as e:
                return "refused" if "permission denied" in str(e) or "must be owner" in str(e) else "error: " + str(e)[:80]
            finally:
                t.rollback()
    out["create_table"] = attempt("create table zz_probe (x int)")
    out["drop_table"] = attempt("drop table company_nodes")
    out["alter_table"] = attempt("alter table company_nodes add column zz_probe int")
    out["update_audit"] = attempt("update audit_events set actor_name = actor_name where false")
    out["delete_audit"] = attempt("delete from audit_events where false")
    out["truncate_audit"] = attempt("truncate audit_events")
u = make_url(url)
plain = u.set(query={k: v for k, v in u.query.items() if k not in ("sslmode", "sslrootcert")}).update_query_dict({"sslmode": "disable"})
try:
    with create_engine(plain).connect() as c:
        out["plain_connection"] = "accepted"
except Exception as e:
    out["plain_connection"] = "refused" if ("no encryption" in str(e) or "pg_hba" in str(e) or "rejected" in str(e)) else "error: " + str(e)[:100]
print("RESULT " + json.dumps(out))
'''

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" " + str(detail)) if detail and not ok else ""))
    if not ok:
        fails.append(name)


def main():
    r = subprocess.run(["docker", "compose", "-f", "docker-compose.prod.yml", "exec", "-T", "backend", "python", "-c", PROBE], capture_output=True, text=True)
    line = next((x for x in r.stdout.splitlines() if x.startswith("RESULT ")), None)
    if r.returncode != 0 or line is None:
        print("Could not run the probe in the backend container. Is the production stack up, and are you in the deploy folder?")
        print((r.stderr or r.stdout)[-600:])
        return 1
    o = json.loads(line[7:])
    check("the application connects as its own role, not as the owner or the superuser", o["user"] == "stai_app", o["user"])
    check("that role is not a superuser and cannot create roles or databases", not o["super"] and not o["createrole"])
    check("the connection is encrypted", o["ssl"], o)
    check("with TLS 1.2 or later", o.get("tls") in ("TLSv1.2", "TLSv1.3"), o.get("tls"))
    check("an unencrypted connection is refused", o["plain_connection"] == "refused", o["plain_connection"])
    check("the application can read and write its data", o["can_select"] and all(o["data"].values()), o["data"])
    check("the tables belong to a different role", o["owner_of_tables"] not in ("stai_app",) and o["owner_of_tables"] == "stai_owner", o["owner_of_tables"])
    check("the application cannot create objects in the schema", not o["schema_create"] and o["create_table"] == "refused", (o["schema_create"], o["create_table"]))
    check("it cannot drop a table", o["drop_table"] == "refused", o["drop_table"])
    check("it cannot alter a table", o["alter_table"] == "refused", o["alter_table"])
    check("the audit log can be read and added to", o["audit"]["SELECT"] and o["audit"]["INSERT"], o["audit"])
    check("but not updated", not o["audit"]["UPDATE"] and o["update_audit"] == "refused", o["update_audit"])
    check("not deleted from", not o["audit"]["DELETE"] and o["delete_audit"] == "refused", o["delete_audit"])
    check("and not truncated", not o["audit"]["TRUNCATE"] and o["truncate_audit"] == "refused", o["truncate_audit"])
    print()
    print("All checks passed." if not fails else f"{len(fails)} check(s) failed: " + "; ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
