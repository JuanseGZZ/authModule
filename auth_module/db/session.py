
from contextlib import contextmanager
from . import SessionLocal

@contextmanager
def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
