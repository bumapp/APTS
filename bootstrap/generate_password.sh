#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  Generate the PostgreSQL password for the APTS `apts` role.
#
#  Idempotent: does nothing if ./tokens/db_password.txt already exists and
#  is non-empty.  Delete the file first if you want a fresh password.
#
#  The password file is mounted read-only into the database container as
#  /run/secrets/db_password and consumed by the postgres image's
#  POSTGRES_PASSWORD_FILE mechanism.  It's also mounted the same way into
#  every Python service — shared/db.py reads it and builds the DSN at
#  runtime, so the raw password never appears in any env var (and therefore
#  never in `docker inspect` output).
# ---------------------------------------------------------------------------
set -euo pipefail

PASSWORD_FILE="${PASSWORD_FILE:-./tokens/db_password.txt}"
TOKEN_DIR="$(dirname "$PASSWORD_FILE")"

mkdir -p "$TOKEN_DIR"
chmod 700 "$TOKEN_DIR"

if [[ -s "$PASSWORD_FILE" ]]; then
    echo "Password file already exists at $PASSWORD_FILE — leaving it alone."
    echo "Delete the file first if you want to regenerate."
    exit 0
fi

# 32 URL-safe characters ~= 190 bits of entropy — well beyond what scram-sha-256
# needs.  We strip characters that could confuse shell/URL parsers just in case
# somebody later tries to embed the password inline somewhere.
openssl rand -base64 48 | tr -d '=+/' | cut -c1-32 > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

echo "==> generated new DB password at $PASSWORD_FILE"
echo "    length: $(wc -c < "$PASSWORD_FILE") bytes, mode: $(stat -c '%a' "$PASSWORD_FILE")"
