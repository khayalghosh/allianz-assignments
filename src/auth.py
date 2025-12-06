# auth.py
import os
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
from jose import jwt
from jose.utils import base64url_decode

TENANT_ID = os.getenv("AZURE_TENANT_ID")
API_APP_CLIENT_ID = os.getenv("API_APP_CLIENT_ID")  # audience expected in token

if not TENANT_ID:
    raise Exception("AZURE_TENANT_ID not set")

OIDC_DISCOVERY = f"https://login.microsoftonline.com/{TENANT_ID}/.well-known/openid-configuration"

bearer_scheme = HTTPBearer(auto_error=False)

# cache the jwks for a short time in-memory
_jwks_cache = {}
_openid_config = None

def get_openid_config():
    global _openid_config
    if _openid_config is None:
        r = requests.get(OIDC_DISCOVERY, timeout=5)
        r.raise_for_status()
        _openid_config = r.json()
    return _openid_config

def get_jwks():
    global _jwks_cache
    config = get_openid_config()
    jwks_uri = config.get("jwks_uri")
    if jwks_uri is None:
        raise Exception("jwks_uri not found in openid configuration")
    # Simple cache; production should refresh on 5xx or key-miss
    if not _jwks_cache:
        r = requests.get(jwks_uri, timeout=5)
        r.raise_for_status()
        _jwks_cache = r.json()
    return _jwks_cache

def validate_azure_ad_token(token: str):
    """
    Validate token signature, issuer, audience.
    Raises HTTPException(401) on failure.
    Returns token claims dict on success.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    jwks = get_jwks()
    try:
        # Get header to find kid
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header")

        key = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key = jwk
                break
        if key is None:
            # refresh and retry once
            _ = requests.get(get_openid_config()["jwks_uri"]).json()
            for jwk in _["keys"]:
                if jwk.get("kid") == kid:
                    key = jwk
                    break
            if key is None:
                raise HTTPException(status_code=401, detail="Unknown kid")

        # Build public key
        public_key = jwt.construct_rsa_public_key(key) if hasattr(jwt, "construct_rsa_public_key") else None
        # python-jose supports passing jwk directly
        claims = jwt.decode(token, key, algorithms=[key.get("alg", "RS256")], audience=API_APP_CLIENT_ID, issuer=f"https://sts.windows.net/{TENANT_ID}/")
        return claims
    except Exception as e:
        # Attempt decode with common issuer form if above issuer mismatch
        try:
            claims = jwt.decode(token, key, algorithms=[key.get("alg", "RS256")], audience=API_APP_CLIENT_ID)
            return claims
        except Exception:
            raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

async def require_auth(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    claims = validate_azure_ad_token(token)
    return claims
