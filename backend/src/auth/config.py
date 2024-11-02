from passlib.context import CryptContext
SECRET_KEY = '1892dhianiandowqd0n'
ALGORITHM = "HS256"
TOKENURl="/api/v1/users/login"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOKEN_EXPIRE_TIME=15