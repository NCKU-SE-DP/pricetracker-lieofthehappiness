from datetime import datetime, timedelta, timezone  
from .config import SECRET_KEY, ALGORITHM, TOKEN_EXPIRE_TIME
from jose import jwt
from .utils import verify
from ..models import User
def check_user_password_is_correct(db, username, password):
    user = db.query(User).filter(User.username == username).first()
    if not verify(password, user.hashed_password):
        return False
    return user
def create_access_token(data, expires_delta=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_TIME)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
