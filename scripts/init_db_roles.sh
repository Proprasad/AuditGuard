#!/bin/sh
# Postgres first-boot hook (mounted into /docker-entrypoint-initdb.d, runs after init.sql). Audit AG-33.
#
# Turns the two privilege-separated roles created by init_db.sql into LOGIN roles with their own passwords, so the
# bank-records (read-only) and case-actions (4-table writer) containers never receive the superuser credentials.
# (Table grants, including the REVOKE on credential tables, live in init_db.sql, which is re-applied at start-up.)
#
# Runs only when the data volume is empty. For an existing volume, run it once by hand:
#   docker compose exec -e POSTGRES_RO_PASSWORD -e POSTGRES_CASE_WRITER_PASSWORD postgres \
#     sh /docker-entrypoint-initdb.d/zz_roles.sh
set -eu
: "${POSTGRES_RO_PASSWORD:?set POSTGRES_RO_PASSWORD (python scripts/init_env.py)}"
: "${POSTGRES_CASE_WRITER_PASSWORD:?set POSTGRES_CASE_WRITER_PASSWORD (python scripts/init_env.py)}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ro_pw="$POSTGRES_RO_PASSWORD" -v cw_pw="$POSTGRES_CASE_WRITER_PASSWORD" <<'SQL'
ALTER ROLE auditguard_ro WITH LOGIN PASSWORD :'ro_pw';
ALTER ROLE auditguard_case_writer WITH LOGIN PASSWORD :'cw_pw';
SQL
