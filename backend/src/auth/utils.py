from .config import pwd_context
def verify(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)