import os
import re
import socket
import psycopg

IDENTITY_TABLES = {
    "users", "resources", "articles", "experts", "navigator_questions",
    "navigator_options", "partner_inquiries", "subscribers", "audit_logs"
}


def _env(name, default=""):
    return (os.getenv(name, default) or "").strip()


def _component_config():
    host = _env("SUPABASE_DB_HOST")
    port = _env("SUPABASE_DB_PORT", "5432")
    dbname = _env("SUPABASE_DB_NAME", "postgres")
    user = _env("SUPABASE_DB_USER")
    password = os.getenv("SUPABASE_DB_PASSWORD", "")
    return host, port, dbname, user, password


def connection_summary():
    url = _env("SUPABASE_DB_URL") or _env("DATABASE_URL")
    if url:
        # Avoid printing secrets: only expose a best-effort host label.
        m = re.search(r"@([^/:?#]+)(?::(\d+))?", url)
        host = m.group(1) if m else "(URL host could not be parsed)"
        port = m.group(2) if m and m.group(2) else "5432"
        return f"URL mode -> host={host}, port={port}"
    host, port, dbname, user, _ = _component_config()
    return f"component mode -> host={host or '(blank)'}, port={port}, db={dbname}, user={user or '(blank)'}"


def validate_connection_config():
    url = _env("SUPABASE_DB_URL") or _env("DATABASE_URL")
    if url:
        placeholders = ["USER:PASSWORD@HOST", "YOUR-PASSWORD", "[YOUR-PASSWORD]", "PROJECT-REF", "[PROJECT-REF]"]
        if any(x in url for x in placeholders):
            raise RuntimeError(
                "SUPABASE_DB_URL still contains example placeholders. "
                "Copy the exact Session pooler connection string from Supabase > Connect, then replace the password."
            )
        return {"mode": "url", "url": url}

    host, port, dbname, user, password = _component_config()
    missing = []
    if not host or "PASTE_" in host:
        missing.append("SUPABASE_DB_HOST")
    if not user or "PASTE_" in user:
        missing.append("SUPABASE_DB_USER")
    if not password:
        missing.append("SUPABASE_DB_PASSWORD")
    if missing:
        raise RuntimeError(
            "Missing Supabase database settings: " + ", ".join(missing) + ". "
            "Use the Session pooler values shown in Supabase Dashboard > Connect."
        )
    try:
        port_i = int(port)
    except ValueError:
        raise RuntimeError("SUPABASE_DB_PORT must be a number, normally 5432 for Session pooler.")

    return {
        "mode": "components",
        "host": host,
        "port": port_i,
        "dbname": dbname or "postgres",
        "user": user,
        "password": password,
    }


def diagnose_dns(host, port=5432):
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return True, None
    except socket.gaierror as exc:
        return False, exc


def connect_postgres():
    cfg = validate_connection_config()
    try:
        if cfg["mode"] == "url":
            return psycopg.connect(cfg["url"], connect_timeout=10)

        ok, dns_error = diagnose_dns(cfg["host"], cfg["port"])
        if not ok:
            raise RuntimeError(
                f"Cannot resolve Supabase host: {cfg['host']}\n"
                "Use Supabase Dashboard > Connect > Session pooler and copy the HOST exactly. "
                "Do not type or guess the pooler host.\n"
                f"DNS error: {dns_error}"
            )

        return psycopg.connect(
            host=cfg["host"],
            port=cfg["port"],
            dbname=cfg["dbname"],
            user=cfg["user"],
            password=cfg["password"],
            sslmode="require",
            connect_timeout=10,
        )
    except psycopg.OperationalError as exc:
        msg = str(exc)
        if "getaddrinfo failed" in msg or "could not translate host name" in msg:
            raise RuntimeError(
                "Supabase host name cannot be resolved. Use the Session pooler connection details from "
                "Supabase Dashboard > Connect. For local Windows networks, Session pooler (port 5432) "
                "is usually the safest choice.\nOriginal error: " + msg
            ) from exc
        raise


class CompatRow:
    def __init__(self, columns, values):
        self._columns = list(columns)
        self._values = tuple(values)
        self._map = dict(zip(self._columns, self._values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def get(self, key, default=None):
        return self._map.get(key, default)

    def keys(self):
        return self._map.keys()

    def items(self):
        return self._map.items()

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return repr(self._map)


class CompatCursor:
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    def _wrap(self, row):
        if row is None:
            return None
        cols = [d.name for d in self._cursor.description] if self._cursor.description else []
        return CompatRow(cols, row)

    def fetchone(self):
        return self._wrap(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not self._cursor.description:
            return rows
        cols = [d.name for d in self._cursor.description]
        return [CompatRow(cols, r) for r in rows]


class CompatConnection:
    def __init__(self):
        self._con = connect_postgres()

    @staticmethod
    def _translate(sql):
        sql = sql.strip()
        sql = sql.replace("?", "%s")
        if re.match(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", sql):
            sql = re.sub(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", sql, count=1)
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        return sql

    def execute(self, sql, params=()):
        translated = self._translate(sql)
        lastrowid = None
        m = re.match(r"(?is)^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", translated)
        if m and m.group(1).lower() in IDENTITY_TABLES and "RETURNING" not in translated.upper() and "ON CONFLICT" not in translated.upper():
            translated = translated.rstrip().rstrip(";") + " RETURNING id"
        cur = self._con.cursor()
        cur.execute(translated, params)
        if "RETURNING id" in translated:
            row = cur.fetchone()
            if row:
                lastrowid = row[0]
        return CompatCursor(cur, lastrowid=lastrowid)

    def executemany(self, sql, seq_of_params):
        translated = self._translate(sql)
        cur = self._con.cursor()
        cur.executemany(translated, seq_of_params)
        return CompatCursor(cur)

    def commit(self):
        self._con.commit()

    def rollback(self):
        self._con.rollback()

    def close(self):
        self._con.close()


def get_db():
    return CompatConnection()
