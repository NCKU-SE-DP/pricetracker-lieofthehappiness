from .config import pwd_context
from .exceptions import PasswordVerificationError
from ..logger.base import logger
from sentry_sdk import capture_exception


def verify(plain_password, hashed_password):
    """
    驗證明文密碼是否與雜湊密碼匹配
    :param plain_password: 明文密碼
    :param hashed_password: 雜湊後的密碼
    :raises PasswordVerificationError: 當密碼驗證失敗時
    :return: 驗證成功返回True
    """
    try:
        if not plain_password or not hashed_password:
            logger.error("Password or hash value cannot be empty")
            raise PasswordVerificationError("Password or hash value cannot be empty")
        result = pwd_context.verify(plain_password, hashed_password)
        if not result:
            logger.error("Password verification failed")
            raise PasswordVerificationError()
        logger.info("Password verification successful")
        return result
    except Exception as e:
        if isinstance(e, PasswordVerificationError):
            capture_exception(e)
            raise
        logger.error(f"Error occurred during password verification: {str(e)}")
        capture_exception(e)
        raise PasswordVerificationError(f"Error occurred during password verification: {str(e)}")