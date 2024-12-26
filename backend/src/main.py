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
from .exceptions import SchedulerStartupError, SchedulerShutdownError
from .logger.base import logger
from sentry_sdk import capture_exception

sentry_sdk.init(
    dsn=App.DSN,
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for tracing.
    traces_sample_rate=App.TRACES_SAMPLE_RATE,
    _experiments={
        # Set continuous_profiling_auto_start to True
        # to automatically start the profiler on when
        # possible.
        "continuous_profiling_auto_start": True,
    },
)

app = FastAPI()
app.include_router(news_router, prefix=App.FASTAPI_PREFIX)
app.include_router(users_router, prefix=App.FASTAPI_PREFIX)
app.include_router(prices_router, prefix=App.FASTAPI_PREFIX)

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
    try:
        db = SessionLocal()
        if db.query(NewsArticle).count() == 0:
            # should change into simple factory pattern
            get_new()
        db.close()
        Scheduler.add_job(get_new, "interval", minutes=App.GET_NEW_INTERVAL_MINUTE)
        Scheduler.start()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {str(e)}")
        capture_exception(e)
        raise SchedulerStartupError(f"Failed to start scheduler: {str(e)}")

@app.on_event("shutdown")
def shutdown_scheduler():
    try:
        Scheduler.shutdown()
    except Exception as e:
        logger.error(f"Failed to shutdown scheduler: {str(e)}")
        capture_exception(e)
        raise SchedulerShutdownError(f"Failed to shutdown scheduler: {str(e)}")