from .db import engine
from .models import Scan  # noqa: F401
from .db import Base

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("DB initialized")
