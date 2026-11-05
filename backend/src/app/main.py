from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.db import get_engine, init_db
from app.core.log import get_logger
from app.api.routes import router

log = get_logger("api")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db(get_engine())
    log.info("database ready")
    yield


app = FastAPI(title="AIPENT", lifespan=lifespan)
app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"ok": True}
