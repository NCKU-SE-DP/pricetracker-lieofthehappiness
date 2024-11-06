from datetime import datetime, timedelta, timezone  
from jose import jwt
from fastapi import Depends
from .config import SECRET_KEY, ALGORITHM, TOKEN_EXPIRE_TIME
from .utils import verify
from .dependencies import oauth2_scheme, session_opener
from ..models import User

def check_user_password_is_correct(db, username, password):
    """
    :param db: 資料庫的 session
    :param username: 使用者的名稱
    :param password: 輸入的密碼
    :return: 如果密碼正確，返回使用者物件；否則返回 False
    """
    user = db.query(User).filter(User.username == username).first()
    if not verify(password, user.hashed_password):
        return False
    return user
def create_access_token(data, expires_delta=None):
    """
    創建一個加密的 JWT（JSON Web Token），用於用戶認證
    :param data: 要編碼進 token 的數據，通常包含用戶相關資訊
    :param expires_delta: Token 的過期時間增量。如果未提供，將使用預設的過期時間
    :return encoded_jwt: 
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_TIME)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user_token(
    token = Depends(oauth2_scheme),
    db = Depends(session_opener)
):
    """
    根據 JWT token 認證使用者
    :param token: 
    :param db:
    :return: 對應於 token 的使用者
    """
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return db.query(User).filter(User.username == payload.get("sub")).first()
