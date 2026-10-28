#!/bin/sh
# Runs once, when the database is first created (the official postgres image runs everything in /docker-entrypoint-initdb.d at that moment only).
#
# Three identities, so that no one of them can do everything:
#   astra_admin  the database's superuser (POSTGRES_USER). Used only by this script and by the health check. The application never connects as it.
#   stai_owner   owns the tables. The API uses it only at start-up, to apply migrations; it cannot create other roles or databases.
#   stai_app     what the running API connects as: it can read and write data and use sequences, and (set by the API at start-up, db/hardening.py) it can only add to the audit
#                log, never change or delete it. It cannot create, alter or drop a table, and statements and idle transactions have time limits.
set -eu
: "${ASTRA_DB_OWNER_PASSWORD:?set ASTRA_DB_OWNER_PASSWORD in .env}"
: "${ASTRA_DB_APP_PASSWORD:?set ASTRA_DB_APP_PASSWORD in .env}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v owner_pw="$ASTRA_DB_OWNER_PASSWORD" -v app_pw="$ASTRA_DB_APP_PASSWORD" -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE stai_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE stai_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 60;
ALTER ROLE stai_app SET statement_timeout = '120s';
ALTER ROLE stai_app SET idle_in_transaction_session_timeout = '60s';
SELECT format('ALTER DATABASE %I OWNER TO stai_owner', :'db') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO stai_owner, stai_app', :'db') \gexec
ALTER SCHEMA public OWNER TO stai_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO stai_app;
ALTER DEFAULT PRIVILEGES FOR ROLE stai_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO stai_app;
ALTER DEFAULT PRIVILEGES FOR ROLE stai_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO stai_app;
SQL
echo "Roles created: stai_owner (owns the tables, migrations) and stai_app (the running API: data only)."
