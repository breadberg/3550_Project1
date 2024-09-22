#Brett Berglund
#9/21/2024

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

# App and constants
app = FastAPI()
KEYS = []
EXPIRATION_PERIOD = timedelta(days=1)

# Helper functions
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize the keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def create_key(kid: str, expiry: datetime):
    private_key_pem, public_key_pem = generate_rsa_key_pair()
    KEYS.append({
        'kid': kid,
        'private_key': private_key_pem,
        'public_key': public_key_pem,
        'expiry': expiry
    })

def get_valid_keys():
    now = datetime.utcnow()
    return [
        {"kid": key["kid"], "public_key": key["public_key"].decode('utf-8')}
        for key in KEYS if key["expiry"] > now
    ]

def get_key_by_kid(kid: str):
    for key in KEYS:
        if key['kid'] == kid:
            return key
    return None

def create_jwt(kid: str, expired=False):
    key = get_key_by_kid(kid)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    expiration_time = datetime.utcnow() + EXPIRATION_PERIOD if not expired else key['expiry']
    payload = {
        "iss": "my-app",
        "sub": "user-123",
        "exp": expiration_time,
        "iat": datetime.utcnow()
    }
    private_key = key['private_key']
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    
    return token

# Create initial keys
create_key(kid="key1", expiry=datetime.utcnow() + EXPIRATION_PERIOD)
create_key(kid="key2", expiry=datetime.utcnow() - timedelta(days=1))  # Expired key

# Endpoints
@app.get("/.well-known/jwks.json")
async def jwks():
    keys = get_valid_keys()
    if not keys:
        raise HTTPException(status_code=404, detail="No valid keys")
    
    jwks_response = {
        "keys": [
            {
                "kid": key["kid"],
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": jwt.utils.base64url_encode(serialization.load_pem_public_key(key['public_key'].encode('utf-8')).public_numbers().n.to_bytes(256, 'big')).decode('utf-8'),
                "e": jwt.utils.base64url_encode(serialization.load_pem_public_key(key['public_key'].encode('utf-8')).public_numbers().e.to_bytes(3, 'big')).decode('utf-8')
            } for key in keys
        ]
    }
    
    return JSONResponse(content=jwks_response)

@app.post("/auth")
async def auth(request: Request):
    params = request.query_params
    expired = "expired" in params
    
    kid = "key2" if expired else "key1"
    
    try:
        token = create_jwt(kid, expired=expired)
    except HTTPException as e:
        raise e
    
    return {"token": token}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
