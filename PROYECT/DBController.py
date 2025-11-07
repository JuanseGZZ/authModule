import os
import psycopg2
import redis
import sqlite3
from dotenv import load_dotenv

# Carga las variables del .env
load_dotenv()


class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class LittleSql(metaclass=SingletonMeta):
    """Base de datos local mínima (SQLite)"""
    def __init__(self):
        self.path = "./little.db"
        self.conn = sqlite3.connect(self.path)
        self._ensure_table()

    def _ensure_table(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS keymaster (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL
            )
        """)
        self.conn.commit()


class RedisDB(metaclass=SingletonMeta):
    """Cliente Redis"""
    def __init__(self):
        self.url = os.getenv("REDIS_URL")
        self.namespace = os.getenv("REDIS_NAMESPACE", "")
        self.client = redis.from_url(self.url)
        try:
            self.client.ping()
            print(f"✅ Redis conectado ({self.url})")
        except redis.ConnectionError:
            print("⚠️  No se pudo conectar a Redis")


class PostgresDB(metaclass=SingletonMeta):
    """Conexión a PostgreSQL"""
    def __init__(self):
        self.host = os.getenv("PG_HOST")
        self.port = os.getenv("PG_PORT")
        self.db = os.getenv("PG_DB")
        self.user = os.getenv("PG_USER")
        self.password = os.getenv("PG_PASSWORD")
        self.sslmode = os.getenv("PG_SSLMODE", "disable")
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.db,
                user=self.user,
                password=self.password,
                sslmode=self.sslmode
            )
            print(f"✅ Postgres conectado ({self.db})")
        except Exception as e:
            print(f"⚠️ Error conectando a Postgres: {e}")


class DBC(metaclass=SingletonMeta):
    """Agregador de conexiones"""
    def __init__(self):
        self.little_sql = LittleSql()
        self.redis = RedisDB()
        self.postgres = PostgresDB()
