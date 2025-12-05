"""
FastAPI VNet creation API using:
- Azure SDK to create VNet + subnets
- SQLite database to store metadata
- Azure AD JWT Bearer token authentication

Run:
  uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os
import sqlite3
import uuid
import json
import time
import requests
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from jose import jwt, JWTError

# Azure
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
 
# --------------------------------------------------------
# ENVIRONMENT VARIABLES
# --------------------------------------------------------
AZ_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
AZ_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZ_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZ_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

RESOURCE_GROUP_NAME = os.getenv("RESOURCE_GROUP_NAME", "rg-vnet-api")
LOCATION = os.getenv("LOCATION", "eastus")
AAD_VALID_TENANT = os.getenv("AAD_VALID_TENANT", AZ_TENANT_ID)

print("Azure subscription ID:", AZ_SUBSCRIPTION_ID)
print("Azure tenant ID:", AZ_TENANT_ID)
print("Azure client ID:", AZ_CLIENT_ID)
print("Azure client secret:", AZ_CLIENT_SECRET)

if not (AZ_SUBSCRIPTION_ID and AZ_TENANT_ID and AZ_CLIENT_ID and AZ_CLIENT_SECRET):
    raise RuntimeError("Missing required Azure environment variables.")

# --------------------------------------------------------
# DATABASE SETUP (SQLite)
# --------------------------------------------------------
DB_PATH = "vnets.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS vnets (
        id TEXT PRIMARY KEY,
        vnet_name TEXT,
        resource_group TEXT,
        subscription_id TEXT,
        location TEXT,
        vnet_id TEXT,
        provisioning_state TEXT,
        azure_response TEXT,
        created_by TEXT,
        created_at REAL
    )
    """)
    conn.commit()
    conn.close()

init_db()

# --------------------------------------------------------
# AZURE CLIENTS
# --------------------------------------------------------
credential = ClientSecretCredential(
    tenant_id=AZ_TENANT_ID,
    client_id=AZ_CLIENT_ID,
    client_secret=AZ_CLIENT_SECRET
)

resource_client = ResourceManagementClient(credential, AZ_SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential, AZ_SUBSCRIPTION_ID)

# --------------------------------------------------------
# JWT VERIFICATION (Azure AD)
# --------------------------------------------------------
OIDC_CONFIG_URL = f"https://login.microsoftonline.com/{AAD_VALID_TENANT}/v2.0/.well-known/openid-configuration"
OIDC_CONFIG = requests.get(OIDC_CONFIG_URL).json()
JWKS = requests.get(OIDC_CONFIG["jwks_uri"]).json()

def verify_token(token: str):
    """
    Validates AAD JWT using JWKS.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        key = next((k for k in JWKS["keys"] if k["kid"] == kid), None)
        # If we didn't find the kid, re-fetch JWKS (keys rotate) and try again.
        if not key:
            try:
                refreshed = requests.get(OIDC_CONFIG["jwks_uri"]).json()
                JWKS.clear()
                JWKS.update(refreshed)
            except Exception:
                pass
            key = next((k for k in JWKS.get("keys", []) if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token header")

        # Build a PEM formatted RSA public key from the JWK 'n' and 'e' values.
        # jose.jwt does not expose construct_rsa_key in some versions; use
        # cryptography to construct the key instead.
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            import base64
            import binascii
            from cryptography import x509

            # If JWK contains x5c (certificate chain), prefer using it
            if key.get("x5c") and len(key.get("x5c")) > 0:
                try:
                    cert_b64 = key["x5c"][0]
                    cert_der = base64.b64decode(cert_b64)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    public_key_obj = cert.public_key()
                    public_key = public_key_obj.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                except Exception:
                    # fall through to n/e method
                    public_key = None
            else:
                public_key = None

            if not public_key:
                def _b64_to_int(b64: str) -> int:
                    # Add padding if necessary
                    b64 += '=' * (-len(b64) % 4)
                    data = base64.urlsafe_b64decode(b64)
                    return int.from_bytes(data, "big")

                n = _b64_to_int(key["n"])
                e = _b64_to_int(key["e"])

                public_numbers = rsa.RSAPublicNumbers(e, n)
                public_key_obj = public_numbers.public_key(default_backend())
                public_key = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to construct public key for token verification")
        issuer = f"https://login.microsoftonline.com/{AAD_VALID_TENANT}/v2.0"

        try:
            # jose.jwt.decode accepts a PEM bytes or string
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=issuer,
                options={"verify_aud": False}
            )
            return payload
        except JWTError as e:
            # Emit diagnostic info to help debug signature verification issues.
            # Avoid printing full token. Print header, matched kid, and a short
            # prefix of the PEM to ensure we used the expected key.
            pem_preview = None
            try:
                if isinstance(public_key, (bytes, bytearray)):
                    pem_preview = public_key.decode('utf-8', errors='ignore')[:300]
                else:
                    pem_preview = str(public_key)[:300]
            except Exception:
                pem_preview = '<unavailable>'

            print("Token verification failed:", str(e))
            print("Token header:", unverified_header)
            print("Matched JWK kid:", key.get('kid'))
            print("PEM preview:\n", pem_preview)

            raise HTTPException(status_code=401, detail=f"Token verification failed: {e}")

    except JWTError as e:
        raise HTTPException(status_code=401, detail=str(e))

# --------------------------------------------------------
# FASTAPI MODELS
# --------------------------------------------------------
class SubnetSpec(BaseModel):
    name: str
    address_prefix: str

class VNetCreateRequest(BaseModel):
    vnet_name: str
    address_prefix: str
    subnets: List[SubnetSpec]

class VNetRecord(BaseModel):
    id: str
    vnet_name: str
    resource_group: str
    subscription_id: str
    location: str
    vnet_id: str
    provisioning_state: str
    azure_response: dict
    created_by: Optional[str]
    created_at: float

# --------------------------------------------------------
# DEPENDENCY - AUTH
# --------------------------------------------------------
async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.split(" ", 1)[1]
    payload = verify_token(token)

    return payload

# --------------------------------------------------------
# UTILS
# --------------------------------------------------------
def store_record(record: VNetRecord):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        INSERT INTO vnets 
        (id, vnet_name, resource_group, subscription_id, location, vnet_id, provisioning_state, azure_response, created_by, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record.id,
        record.vnet_name,
        record.resource_group,
        record.subscription_id,
        record.location,
        record.vnet_id,
        record.provisioning_state,
        json.dumps(record.azure_response),
        record.created_by,
        record.created_at
    ))

    conn.commit()
    conn.close()

# --------------------------------------------------------
# API
# --------------------------------------------------------
app = FastAPI(title="Azure VNet API (SQLite storage)")

@app.post("/vnet", response_model=VNetRecord)
async def create_vnet(req: VNetCreateRequest, user=Depends(get_current_user)):

    # ensure RG exists
    resource_client.resource_groups.create_or_update(
        RESOURCE_GROUP_NAME, {"location": LOCATION}
    )

    # create VNet with subnets
    vnet_params = {
        "location": LOCATION,
        "address_space": {"address_prefixes": [req.address_prefix]},
        "subnets": [{"name": s.name, "address_prefix": s.address_prefix} for s in req.subnets]
    }

    poller = network_client.virtual_networks.begin_create_or_update(
        RESOURCE_GROUP_NAME,
        req.vnet_name,
        vnet_params
    )

    result = poller.result()

    record_id = str(uuid.uuid4())

    record = VNetRecord(
        id=record_id,
        vnet_name=req.vnet_name,
        resource_group=RESOURCE_GROUP_NAME,
        subscription_id=AZ_SUBSCRIPTION_ID,
        location=LOCATION,
        vnet_id=result.id,
        provisioning_state=result.provisioning_state,
        azure_response=result.as_dict(),
        created_by=user.get("preferred_username"),
        created_at=time.time()
    )

    store_record(record)

    return record

@app.get("/vnet/{record_id}", response_model=VNetRecord)
async def get_vnet(record_id: str, user=Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    row = c.execute("SELECT * FROM vnets WHERE id = ?", (record_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Record not found")

    return {
        "id": row[0],
        "vnet_name": row[1],
        "resource_group": row[2],
        "subscription_id": row[3],
        "location": row[4],
        "vnet_id": row[5],
        "provisioning_state": row[6],
        "azure_response": json.loads(row[7]),
        "created_by": row[8],
        "created_at": row[9]
    }

@app.get("/vnet", response_model=List[VNetRecord])
async def list_vnets(user=Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    with conn:
        rows = conn.execute("SELECT * FROM vnets").fetchall()
    return [
        {
            "id": row["id"],
            "vnet_name": row["vnet_name"],
            "resource_group": row["resource_group"],
            "subscription_id": row["subscription_id"],
            "location": row["location"],
            "vnet_id": row["vnet_id"],
            "provisioning_state": row["provisioning_state"],
            "azure_response": json.loads(row["azure_response"]) if row["azure_response"] else {},
            "created_by": row["created_by"],
            "created_at": row["created_at"]
        }
        for row in rows
    ]

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
