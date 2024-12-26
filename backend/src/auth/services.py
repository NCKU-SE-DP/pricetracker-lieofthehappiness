from datetime import datetime, timedelta, timezone  
from jose import jwt
from fastapi import Depends
from sentry_sdk import capture_exception
from .config import SECRET_KEY, ALGORITHM, TOKEN_EXPIRE_TIME
from .utils import verify
from ..database import oauth2_scheme, session_opener
from ..models import User
from .exceptions import UserNotFoundException, PasswordVerificationError, TokenDecodeError
from ..logger.base import logger

def check_user_password_is_correct(db, username, password):
    """
    :param db: 資料庫的 session
    :param username: 使用者的名稱
    :param password: 輸入的密碼
    :return: 如果密碼正確，返回使用者物件
    :raises UserNotFoundException: 當使用者不存在時
    :raises PasswordVerificationError: 當密碼驗證失敗時
    """
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            logger.error(f"User {username} does not exist")
            raise UserNotFoundException(f"User {username} not found")
        if not verify(password, user.hashed_password):
            logger.error(f"Password verification failed for user {username}")
            raise PasswordVerificationError()
        logger.info(f"Password verification successful for user {username}")
        return user
    except Exception as e:
        logger.error(f"Error checking user password: {str(e)}")
        capture_exception(e)
        raise

def create_access_token(data, expires_delta=None):
    """
    創建一個加密的 JWT（JSON Web Token），用於用戶認證
    :param data: 要編碼進 token 的數據，通常包含用戶相關資訊
    :param expires_delta: Token 的過期時間增量。如果未提供，將使用預設的過期時間
    :return encoded_jwt: 加密後的 JWT token
    """
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_TIME)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Successfully created access token for user {data.get('sub')}")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {str(e)}")
        capture_exception(e)
        raise

def authenticate_user_token(
    token = Depends(oauth2_scheme),
    db = Depends(session_opener)
):
    """
    根據 JWT token 認證使用者
    :param token: JWT token
    :param db: 資料庫 session
    :return: 對應於 token 的使用者
    :raises TokenDecodeError: 當 token 解碼失敗時
    :raises UserNotFoundException: 當使用者不存在時
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.username == payload.get("sub")).first()
        if not user:
            logger.error(f"User corresponding to token not found")
            raise UserNotFoundException()
        logger.info(f"Token verification successful for user {user.username}")
        return user
    except jwt.JWTError as e:
        logger.error(f"Token decoding failed: {str(e)}")
        capture_exception(e)
        raise TokenDecodeError()
    except Exception as e:
        logger.error(f"Error authenticating user token: {str(e)}")
        capture_exception(e)
        raise
