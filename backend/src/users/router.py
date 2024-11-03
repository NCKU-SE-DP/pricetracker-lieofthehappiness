from fastapi import Depends
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm, FastAPI
from sqlalchemy.orm import Session
from datetime import timedelta
from sqlalchemy.orm import Session
from .constants import USER_ACCESS_EXPIRE_TIME
from ..models import User
from ..auth.services import check_user_password_is_correct, create_access_token 
from ..models import User
from ..auth.schemas import UserAuthSchema
from ..auth.config import pwd_context
from ..auth.dependencies import session_opener, authenticate_user_token
app=FastAPI()
@app.post("/api/v1/users/login")
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(session_opener)
):
    user = check_user_password_is_correct(db, form_data.username, form_data.password)
    access_token = create_access_token(
        data={"sub": str(user.username)}, expires_delta=timedelta(minutes=USER_ACCESS_EXPIRE_TIME)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/v1/users/register")
def create_user(user: UserAuthSchema, db: Session = Depends(session_opener)):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/api/v1/users/me")
def read_users_me(user=Depends(authenticate_user_token)):
    return {"username": user.username}