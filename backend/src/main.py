from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
import sentry_sdk
from .models import NewsArticle
from .config import App
from .database import SessionLocal
from .news.services import get_new
from .prices.router import router as prices_router
from .news.router import router as news_router
from .users.router import router as users_router


app = FastAPI()
app.include_router(news_router, prefix=App.FASTAPI_PREFIX)
app.include_router(users_router, prefix=App.FASTAPI_PREFIX)
app.include_router(prices_router, prefix=App.FASTAPI_PREFIX)
sentry_sdk.init(
    dsn=App.DSN,
    traces_sample_rate=App.TRACES_SAMPLE_RATE,
    profiles_sample_rate=App.PROFILES_SAMPLE_RATE,
)
Scheduler=BackgroundScheduler()

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
    Scheduler.add_job(get_new, "interval", minutes=App.GET_NEW_INTERVAL_MINUTE)
    Scheduler.start()

@app.on_event("shutdown")
def shutdown_scheduler():
    Scheduler.shutdown()