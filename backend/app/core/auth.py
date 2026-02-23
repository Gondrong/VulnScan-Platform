import base64, hashlib, hmac, json, time
from fastapi import HTTPException, Request
from app.core.config import settings

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_jwt(payload: dict, ttl_seconds: int = 3600*12) -> str:
    now = int(time.time())
    payload = dict(payload)
    payload["iat"] = now
    payload["exp"] = now + ttl_seconds
    header = {"alg":"HS256","typ":"JWT"}
    h = _b64u(json.dumps(header, separators=(",",":")).encode())
    p = _b64u(json.dumps(payload, separators=(",",":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"

def verify_jwt(token: str) -> dict:
    try:
        h, p, s = token.split(".")
        msg = f"{h}.{p}".encode()
        sig = _b64u_decode(s)
        exp_sig = hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp_sig):
            raise ValueError("bad signature")
        payload = json.loads(_b64u_decode(p))
        if int(time.time()) > int(payload["exp"]):
            raise ValueError("expired")
        return payload
    except Exception:
        raise HTTPException(401, "invalid token")

def get_bearer_token(req: Request) -> str:
    auth = req.headers.get("Authorization","")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    return auth.split(" ",1)[1].strip()