import shutil
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.database import engine, Base
from app.errors import register_exception_handlers
from app.routes.scans import router

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    if shutil.which(settings.NMAP_PATH) is None:
        raise RuntimeError(
            f"nmap not found at '{settings.NMAP_PATH}'. "
            "Install nmap and ensure it is on PATH before starting this service."
        )

    logger.info("nmap found at: %s", shutil.which(settings.NMAP_PATH))
    logger.info("Nmap REST API started. DEMO_MODE=%s", settings.DEMO_MODE)
    yield


app = FastAPI(title="Nmap REST API", version="1.0.0", lifespan=lifespan)
register_exception_handlers(app)
app.include_router(router)
