# main.py
import os
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from models import init_db, SessionLocal, VNetRecord
from azure_client import create_vnet_with_subnets
from auth import require_auth
from sqlalchemy.orm import Session

app = FastAPI(title="Azure VNet API")

# Pydantic models
class SubnetSpec(BaseModel):
    name: str
    address_prefix: str

class CreateVNetRequest(BaseModel):
    name: str = Field(..., example="my-vnet")
    address_prefixes: list[str] = Field(..., example=["10.10.0.0/16"])
    subnets: list[SubnetSpec]

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def startup():
    init_db()

@app.post("/vnets", dependencies=[Depends(require_auth)])
def create_vnet(req: CreateVNetRequest, db: Session = Depends(get_db)):
    # Basic name checks could be added.
    try:
        result = create_vnet_with_subnets(req.name, req.address_prefixes, [s.dict() for s in req.subnets])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Azure creation failed: {e}")

    record = VNetRecord(
        name=req.name,
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        resource_group=os.getenv("AZURE_RESOURCE_GROUP"),
        location=os.getenv("AZURE_LOCATION"),
        azure_response=result
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"id": record.id, "vnet": result}

@app.get("/vnets", dependencies=[Depends(require_auth)])
def list_vnets(db: Session = Depends(get_db)):
    rows = db.query(VNetRecord).order_by(VNetRecord.created_at.desc()).all()
    return [{"id": r.id, "name": r.name, "created_at": r.created_at.isoformat(), "azure_response": r.azure_response} for r in rows]

@app.get("/vnets/{vnet_id}", dependencies=[Depends(require_auth)])
def get_vnet(vnet_id: int, db: Session = Depends(get_db)):
    r = db.query(VNetRecord).filter(VNetRecord.id == vnet_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="VNet record not found")
    return {"id": r.id, "name": r.name, "azure_response": r.azure_response, "created_at": r.created_at.isoformat()}
