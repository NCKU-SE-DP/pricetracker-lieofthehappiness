from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt
from ..database import engine
from fastapi import Depends
from .config import SECRET_KEY, ALGORITHM, TOKENURl
from ..models import User
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKENURl)
def session_opener():
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()
        
def authenticate_user_token(
    token = Depends(oauth2_scheme),
    db = Depends(session_opener)
):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return db.query(User).filter(User.username == payload.get("sub")).first()
