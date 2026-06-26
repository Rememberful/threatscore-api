import os, secrets, hashlib
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET  = os.getenv("JWT_SECRET", "changeme")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_HOURS = 24


def hash_password(password: str) -> str:
    # bcrypt has a 72-byte limit; truncate to be safe
    return pwd_context.hash(password[:72])


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:72], hashed)


def create_jwt(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": str(user_id), "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)


def decode_jwt(token: str) -> int:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    return int(payload["sub"])


def generate_api_key() -> tuple[str, str]:
    """Returns (plain_key, hashed_key)"""
    plain = "ts_" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(plain.encode()).hexdigest()
    return plain, hashed


def hash_api_key(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()
