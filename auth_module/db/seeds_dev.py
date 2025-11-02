
from db.session import get_session
from services.auth_service import AuthService

def seed():
    from sqlalchemy.exc import IntegrityError
    with get_session() as db:
        svc = AuthService(db)
        try:
            svc.create_user("demo@example.com", "demo123")
            print("Seeded demo user: demo@example.com / demo123")
        except IntegrityError:
            print("Demo user already exists")

if __name__ == "__main__":
    seed()
