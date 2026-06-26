from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, Text, Boolean, Float, ForeignKey, TIMESTAMP, func
from sqlalchemy.dialects.postgresql import JSONB
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id           = Column(Integer, primary_key=True)
    email        = Column(Text, unique=True, nullable=False)
    password_hash= Column(Text, nullable=False)
    created_at   = Column(TIMESTAMP, server_default=func.now())


class ApiKey(Base):
    __tablename__ = "api_keys"
    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    key_hash   = Column(Text, unique=True, nullable=False)
    label      = Column(Text)
    is_active  = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=func.now())


class ScoreLog(Base):
    __tablename__ = "score_logs"
    id                     = Column(Integer, primary_key=True)
    api_key_id             = Column(Integer, ForeignKey("api_keys.id"))
    srcip                  = Column(Text)
    sport                  = Column(Integer)
    proto                  = Column(Text)
    service                = Column(Text)
    sbytes                 = Column(Integer)
    dbytes                 = Column(Integer)
    dur                    = Column(Float)
    sttl                   = Column(Integer)
    threat_score           = Column(Integer)
    verdict                = Column(Text)
    closest_attack_profile = Column(Text)
    confidence             = Column(Float)
    flags                  = Column(JSONB)
    recommendation         = Column(Text)
    created_at             = Column(TIMESTAMP, server_default=func.now())


# ── Dependency ────────────────────────────────────────────────────────────────

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
