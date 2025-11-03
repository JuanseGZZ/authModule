
import os, psycopg
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from bcrypt import hashpw, gensalt

DB_DSN = os.getenv("DB_DSN", "postgresql://postgres:postgres@localhost:5432/postgres")

class DB:
    def __init__(self):
        self.dsn = DB_DSN
        self._ensure_schema()

    def _conn(self):
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def _ensure_schema(self):
        # Minimal schema for MVP. TODO: migration files reales.
        sql = """
        create table if not exists users(
            id uuid primary key default gen_random_uuid(),
            email text unique not null,
            password_hash bytea not null,
            created_at timestamptz default now(),
            updated_at timestamptz default now()
        );
        create table if not exists refresh_tokens(
            id uuid primary key default gen_random_uuid(),
            user_id uuid not null references users(id) on delete cascade,
            token_hash bytea unique not null,
            issued_at timestamptz default now(),
            expires_at timestamptz not null,
            revoked_at timestamptz,
            parent_id uuid references refresh_tokens(id),
            user_agent text,
            ip inet
        );
        """
        with self._conn() as c:
            c.execute(sql)

    def create_user(self, email: str, password: str) -> Dict[str, Any]:
        with self._conn() as c:
            if c.execute("select 1 from users where email=%s", (email,)).fetchone():
                raise ValueError("email ya registrado")
            pw = hashpw(password.encode("utf-8"), gensalt())
            row = c.execute("insert into users(email, password_hash) values(%s,%s) returning id,email", (email, pw)).fetchone()
            return {"id": str(row["id"]), "email": row["email"]}

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("select id,email,password_hash from users where email=%s", (email,)).fetchone()
            return row

    def store_refresh(self, user_id: str, token_hash: bytes, ttl_days: int, parent_id: Optional[str], user_agent: Optional[str], ip: Optional[str]):
        exp = datetime.now(timezone.utc) + timedelta(days=ttl_days)
        with self._conn() as c:
            c.execute(
                "insert into refresh_tokens(user_id, token_hash, expires_at, parent_id, user_agent, ip) values(%s,%s,%s,%s,%s,%s)",
                (user_id, token_hash, exp, parent_id, user_agent, ip)
            )

    def get_refresh_by_hash(self, token_hash: bytes) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            return c.execute("select * from refresh_tokens where token_hash=%s", (token_hash,)).fetchone()

    def revoke_refresh(self, refresh_id: str):
        with self._conn() as c:
            c.execute("update refresh_tokens set revoked_at=now() where id=%s", (refresh_id,))


def get_user_by_id(self, user_id: str):
    with self._conn() as c:
        return c.execute("select id,email from users where id=%s", (user_id,)).fetchone()
