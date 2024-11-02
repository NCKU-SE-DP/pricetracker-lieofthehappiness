from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
import sentry_sdk
from .models import NewsArticle
from .config import App
from .database import engine
from .news import get_new
app = FastAPI()
sentry_sdk.init(
    dsn=App.DSN,
    traces_sample_rate=App.TRACES_SAMPLE_RATE,
    profiles_sample_rate=App.PROFILES_SAMPLE_RATE,
)
Scheduler=BackgroundScheduler()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app.add_middleware(
    CORSMiddleware,  # noqa
    allow_origins=[App.LOCALHOST],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def start_scheduler():
    db = SessionLocal()
    if db.query(NewsArticle).count() == 0:
        # should change into simple factory pattern
        get_new()
    db.close()
    Scheduler.add_job(get_new, "interval", minutes=100)
    Scheduler.start()

@app.on_event("shutdown")
def shutdown_scheduler():
    Scheduler.shutdown()