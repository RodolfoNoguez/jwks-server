from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import jwt
import time
from keymanager import KeyManager

# initiates the fastapi and key manager
app = FastAPI()
km = KeyManager()

# jwks endpoints
@app.get("/.well-known/jwks.json")
@app.get("/jwks")
async def jwks():
    return JSONResponse(content={"keys": [k.to_jwk() for k in km.get_unexpired_keys()]})


# generate keys
km.generate_key("kid-valid", ttl_seconds=24*3600)
km.generate_key("kid-expired", ttl_seconds=-7200)  

#  auth endpoint
@app.post("/auth")
async def auth(request: Request):
    expired_param = request.query_params.get("expired", "0")

    # generate a expired token
    if expired_param == "1":
        key = km.get_expired()
        if not key:
            raise HTTPException(status_code=500, detail="No expired key available")

        payload = {
            "sub": "user-123",
            "iss": "jwks-server",
            "iat": int(time.time()) - 3600,  
            "exp": int(key.expires_at)     
        }

        token = jwt.encode(payload, key.private_key, algorithm="RS256", headers={"kid": key.kid})
        return {"token": token, "kid": key.kid}





    # generate a token that is valid
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
    # sign the jwk with a good key
    token = jwt.encode(payload, key.private_key, algorithm="RS256", headers={"kid": key.kid})
    return {"token": token, "kid": key.kid}