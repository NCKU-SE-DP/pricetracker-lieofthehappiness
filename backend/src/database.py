from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from fastapi.security import OAuth2PasswordBearer
from .config import Database
from .logger.base import logger
from sentry_sdk import capture_exception
from .exceptions import DatabaseConnectionError


Base = declarative_base()
engine = create_engine("sqlite:///news_database.db", echo=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=Database.TOKENURl)

def session_opener():
    session=None
    try:
        session = Session(bind=engine)
        yield session
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        capture_exception(e)
        raise DatabaseConnectionError(f"Database connection error: {str(e)}")
    finally:
        if session: 
            session.close()