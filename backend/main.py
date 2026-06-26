from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from db import init_db
from services.ml_service import load_models
from routers import auth, score, dashboard


limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    load_models()
    yield
    # Shutdown — nothing needed


app = FastAPI(title="ThreatScore API", version="1.0.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,      prefix="/auth")
app.include_router(score.router,     prefix="/api")
app.include_router(dashboard.router, prefix="/dashboard")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "ThreatScore API"}
