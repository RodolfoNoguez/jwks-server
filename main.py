from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import jwt
import time
from keymanager import KeyManager

app = FastAPI()
km = KeyManager()

# generate one unexpired and one expired key
km.generate_key("kid-valid", ttl_seconds=24*3600)   # valid for 1 day
# km.generate_key("kid-expired", ttl_seconds=-3600)   # expired already


@app.get("/.well-known/jwks.json")
@app.get("/jwks")
async def jwks():
    return JSONResponse(content={"keys": [k.to_jwk() for k in km.get_unexpired_keys()]})


# generate keys
km.generate_key("kid-valid", ttl_seconds=24*3600)
km.generate_key("kid-expired", ttl_seconds=-7200)   # expired 2 hours ago

@app.post("/auth")
async def auth(request: Request):
    expired_param = request.query_params.get("expired", "0")

    if expired_param == "1":
        key = km.get_expired()
        if not key:
            raise HTTPException(status_code=500, detail="No expired key available")

        payload = {
            "sub": "user-123",
            "iss": "jwks-server",
            "iat": int(time.time()) - 3600,  # issued 1 hour ago
            "exp": int(key.expires_at)     # expired 1 minute ago
        }

        token = jwt.encode(payload, key.private_key, algorithm="RS256", headers={"kid": key.kid})
        return {"token": token, "kid": key.kid}





    # normal case
    key = km.get_any_unexpired()
    if not key:
        raise HTTPException(status_code=500, detail="No valid key")
    exp = int(time.time()) + 3600
    payload = {
        "sub": "user-123",
        "iss": "jwks-server",
        "iat": int(time.time()),
        "exp": exp,
    }
    token = jwt.encode(payload, key.private_key, algorithm="RS256", headers={"kid": key.kid})
    return {"token": token, "kid": key.kid}
