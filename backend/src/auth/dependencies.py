
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from ..database import engine
from .config import TOKENURl
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKENURl)
def session_opener():
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        

