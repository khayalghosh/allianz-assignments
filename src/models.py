# models.py
import os
import datetime
from sqlalchemy import Column, Integer, String, JSON, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Default to local sqlite file for easy testing
DATABASE_URL = os.getenv("DB_URL", "sqlite:///./vnet.db")

# For SQLite we need check_same_thread; for other DBs connect_args should be empty
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class VNetRecord(Base):
    __tablename__ = "vnet_records"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    subscription_id = Column(String)
    resource_group = Column(String)
    location = Column(String)
    azure_response = Column(JSON)   # store Azure's creation response or summary
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
