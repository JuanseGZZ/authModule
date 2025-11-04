import psycopg
from psycopg_pool import ConnectionPool
from config import CFG

def _build_dsn() -> str:
    return (
        f"host={CFG.DB_HOST} port={CFG.DB_PORT} dbname={CFG.DB_NAME} "
        f"user={CFG.DB_USER} password={CFG.DB_PASSWORD} connect_timeout={CFG.DB_CONNECT_TIMEOUT}"
    )

POOL: ConnectionPool = ConnectionPool(
    conninfo=_build_dsn(),
    min_size=CFG.DB_MIN_CONN,
    max_size=CFG.DB_MAX_CONN,
    kwargs={"autocommit": True}
)

def get_conn():
    return POOL.connection()
