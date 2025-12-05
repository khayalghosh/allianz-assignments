# app.py
import os
import time
import json
import logging
import ipaddress
from typing import List, Optional
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Azure SDK
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError

# JWT validation
import jwt
from jwt import PyJWKClient

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vnet-api")

# ---------- Config (env vars) ----------
# DATABASE_URL: prefer a Postgres URL like:
#   postgres://user:pass@host:5432/dbname
# or a SQLAlchemy-style URL:
#   postgresql+psycopg2://user:pass@host:5432/dbname
# If none provided, we fall back to a local SQLite file (useful for dev).
raw_database_url = os.environ.get("DATABASE_URL", "")

# Some platforms provide DATABASE_URL using the legacy 'postgres://' scheme.
# SQLAlchemy/psycopg2 expects 'postgresql://' or 'postgresql+psycopg2://'.
if raw_database_url.startswith("postgres://"):
    DATABASE_URL = raw_database_url.replace("postgres://", "postgresql://", 1)
elif raw_database_url:
    DATABASE_URL = raw_database_url
else:
    # fallback to sqlite for local dev
    DATABASE_URL = os.environ.get("SQLITE_DATABASE_URL", "sqlite:///./local.db")
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")

# For validating incoming bearer tokens
AZURE_AD_TENANT = os.environ.get("AZURE_AD_TENANT") or AZURE_TENANT_ID
AZURE_AD_CLIENT_ID = os.environ.get("AZURE_AD_CLIENT_ID")  # optional audience validation

CREATE_RG_IF_MISSING = os.environ.get("CREATE_RG_IF_MISSING", "true").lower() in ("1", "true", "yes")

# Basic checks
if not SUBSCRIPTION_ID:
    raise RuntimeError("AZURE_SUBSCRIPTION_ID must be set in environment")
if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET]):
    raise RuntimeError("AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET must be set for client credentials auth")

# ---------- DB Setup ----------
# Configure engine options differently for sqlite vs postgres
engine_kwargs = {"echo": False, "future": True}
connect_args = {}
if DATABASE_URL.startswith("sqlite:"):
    # sqlite needs the check_same_thread arg for file-based DBs when using threads
    connect_args = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, connect_args=connect_args, **engine_kwargs)
else:
    # For Postgres use reasonable pool settings and enable pool_pre_ping for resiliency
    engine_kwargs.update({"pool_pre_ping": True})
    engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class VNetRecord(Base):
    __tablename__ = "vnets"
    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    resource_group = Column(String, nullable=False)
    location = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    raw = Column(JSON, nullable=False)
    status = Column(String, default="unknown")
    notes = Column(Text, nullable=True)
    idempotency_key = Column(String(128), nullable=True, unique=True)

    __table_args__ = (
        UniqueConstraint('idempotency_key', name='uq_idempotency_key'),
    )

Base.metadata.create_all(bind=engine)

# ---------- Pydantic models ----------
class SubnetSpec(BaseModel):
    name: str
    address_prefix: str

    @validator("address_prefix")
    def valid_cidr(cls, v):
        try:
            ipaddress.ip_network(v)
        except Exception:
            raise ValueError(f"Invalid CIDR: {v}")
        return v

class VNetCreateSpec(BaseModel):
    name: str = Field(..., description="VNet name")
    resource_group: str
    location: str
    address_space: List[str] = Field(..., description="VNet address prefixes, e.g. ['10.0.0.0/16']")
    subnets: List[SubnetSpec]

    @validator("address_space", each_item=True)
    def valid_address_space(cls, v):
        try:
            ipaddress.ip_network(v)
        except Exception:
            raise ValueError(f"Invalid CIDR in address_space: {v}")
        return v

class VNetOut(BaseModel):
    id: int
    resource_id: str
    name: str
    resource_group: str
    location: str
    created_at: datetime
    updated_at: Optional[datetime]
    raw: dict
    status: str

# ---------- Auth (Azure AD JWT validation) ----------
OIDC_CONFIG_CACHE = {}
JWKS_CLIENT_CACHE = {}

def get_openid_config(tenant: str):
    if tenant in OIDC_CONFIG_CACHE:
        return OIDC_CONFIG_CACHE[tenant]
    url = f"https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    cfg = r.json()
    OIDC_CONFIG_CACHE[tenant] = cfg
    return cfg

def validate_token(token: str):
    if not AZURE_AD_TENANT:
        raise RuntimeError("AZURE_AD_TENANT is required for token validation")
    oidc = get_openid_config(AZURE_AD_TENANT)
    jwks_uri = oidc["jwks_uri"]
    if jwks_uri not in JWKS_CLIENT_CACHE:
        JWKS_CLIENT_CACHE[jwks_uri] = PyJWKClient(jwks_uri)
    jwk_client = JWKS_CLIENT_CACHE[jwks_uri]
    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AZURE_AD_CLIENT_ID if AZURE_AD_CLIENT_ID else None,
            issuer=oidc.get("issuer"),
            options={"verify_aud": True if AZURE_AD_CLIENT_ID else False}
        )
    except Exception as ex:
        raise HTTPException(status_code=401, detail=f"Invalid token: {ex}")
    return decoded

auth_scheme = HTTPBearer(auto_error=False)

async def require_auth(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    token = credentials.credentials
    claims = validate_token(token)
    return claims

# ---------- Azure client factory using App Registration (ClientSecretCredential) ----------
def get_azure_credentials():
    """
    Always use ClientSecretCredential backed by the App Registration (client credentials).
    Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in env.
    """
    return ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )

def get_network_client():
    cred = get_azure_credentials()
    return NetworkManagementClient(cred, SUBSCRIPTION_ID)

def get_resource_client():
    cred = get_azure_credentials()
    return ResourceManagementClient(cred, SUBSCRIPTION_ID)

# ---------- App and DB dependency ----------
app = FastAPI(title="Azure VNet Provisioning API (App Registration auth)")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- Utilities ----------
def ensure_resource_group(resource_client, rg_name, location):
    try:
        rg = resource_client.resource_groups.get(rg_name)
        return rg
    except HttpResponseError as e:
        # If missing and allowed, create
        if hasattr(e, "status_code") and e.status_code == 404 and CREATE_RG_IF_MISSING:
            body = {"location": location}
            resource_client.resource_groups.create_or_update(rg_name, body)
            return resource_client.resource_groups.get(rg_name)
        raise

def azure_create_vnet_with_retry(network_client, rg, vnet_name, vnet_params, max_retries=3):
    attempt = 0
    while True:
        try:
            operation = network_client.virtual_networks.begin_create_or_update(rg, vnet_name, vnet_params)
            result = operation.result(timeout=180)
            return result
        except Exception as ex:
            attempt += 1
            logger.warning("Azure create vnet attempt %d failed: %s", attempt, ex)
            if attempt >= max_retries:
                logger.exception("Max retries reached; failing")
                raise
            backoff = 2 ** attempt
            time.sleep(backoff)

# ---------- Endpoints ----------
@app.post("/vnets", response_model=VNetOut, status_code=201)
def create_vnet(
    payload: VNetCreateSpec,
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    claims: dict = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """
    Create an Azure VNet with subnets (multiple subnets supported).
    Any authenticated user (Azure AD token) can call this.
    Provide Idempotency-Key header to avoid duplicates.
    """
    # Idempotency: check if key already used
    if idempotency_key:
        existing = db.query(VNetRecord).filter(VNetRecord.idempotency_key == idempotency_key).first()
        if existing:
            logger.info("Returning existing record for idempotency key %s", idempotency_key)
            return VNetOut(
                id=existing.id,
                resource_id=existing.resource_id,
                name=existing.name,
                resource_group=existing.resource_group,
                location=existing.location,
                created_at=existing.created_at,
                updated_at=existing.updated_at,
                raw=existing.raw,
                status=existing.status,
            )

    network_client = get_network_client()
    resource_client = get_resource_client()

    # Ensure resource group exists (optional)
    try:
        ensure_resource_group(resource_client, payload.resource_group, payload.location)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=f"Resource group check/create failed: {ex}")

    vnet_name = payload.name
    vnet_params = {
        "location": payload.location,
        "address_space": {"address_prefixes": payload.address_space},
        "subnets": [{"name": s.name, "address_prefix": s.address_prefix} for s in payload.subnets],
    }

    try:
        vnet_result = azure_create_vnet_with_retry(network_client, payload.resource_group, vnet_name, vnet_params)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Azure create failed: {ex}")

    # serialize result
    try:
        raw = vnet_result.as_dict() if hasattr(vnet_result, "as_dict") else json.loads(json.dumps(vnet_result.__dict__, default=str))
    except Exception:
        raw = {"repr": str(vnet_result)}

    resource_id = raw.get("id") or f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{payload.resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}"
    provisioning_state = raw.get("provisioning_state") or raw.get("provisioningState") or "Succeeded"

    # store in DB; idempotency_key may be None
    record = VNetRecord(
        resource_id=resource_id,
        name=vnet_name,
        resource_group=payload.resource_group,
        location=payload.location,
        raw=raw,
        status=provisioning_state,
        idempotency_key=idempotency_key,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as ex:
        db.rollback()
        # If idempotency constraint violated due to race, fetch existing
        msg = str(ex).lower()
        if idempotency_key and ("uq_idempotency_key" in msg or "unique constraint" in msg):
            existing = db.query(VNetRecord).filter(VNetRecord.idempotency_key == idempotency_key).first()
            if existing:
                return VNetOut(
                    id=existing.id,
                    resource_id=existing.resource_id,
                    name=existing.name,
                    resource_group=existing.resource_group,
                    location=existing.location,
                    created_at=existing.created_at,
                    updated_at=existing.updated_at,
                    raw=existing.raw,
                    status=existing.status,
                )
        raise HTTPException(status_code=500, detail=f"DB error: {ex}")

    return VNetOut(
        id=record.id,
        resource_id=record.resource_id,
        name=record.name,
        resource_group=record.resource_group,
        location=record.location,
        created_at=record.created_at,
        updated_at=record.updated_at,
        raw=record.raw,
        status=record.status,
    )

@app.get("/vnets", response_model=List[VNetOut])
def list_vnets(claims: dict = Depends(require_auth), db: Session = Depends(get_db)):
    rows = db.query(VNetRecord).order_by(VNetRecord.created_at.desc()).all()
    return [
        VNetOut(
            id=r.id,
            resource_id=r.resource_id,
            name=r.name,
            resource_group=r.resource_group,
            location=r.location,
            created_at=r.created_at,
            updated_at=r.updated_at,
            raw=r.raw,
            status=r.status,
        ) for r in rows
    ]

@app.get("/vnets/{id}", response_model=VNetOut)
def get_vnet(id: int, claims: dict = Depends(require_auth), db: Session = Depends(get_db)):
    r = db.query(VNetRecord).filter(VNetRecord.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail="VNet record not found")
    return VNetOut(
        id=r.id,
        resource_id=r.resource_id,
        name=r.name,
        resource_group=r.resource_group,
        location=r.location,
        created_at=r.created_at,
        updated_at=r.updated_at,
        raw=r.raw,
        status=r.status,
    )

@app.get("/healthz")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
