#!/usr/bin/env python3
"""
Database configuration and models for RAT detector
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, BigInteger, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import JSONB
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanResult(Base):
    """Model for storing scan results"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), unique=True, index=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    prediction = Column(String(20), nullable=False)  # 'safe' or 'malicious'
    probability_malicious = Column(Float, nullable=False)
    features = Column(JSONB)  # Store extracted features as JSON
    file_size = Column(BigInteger)
    s3_location = Column(String(500))  # S3 bucket path
    processing_time_seconds = Column(Float)
    user_ip = Column(String(45))  # Support IPv6
    user_agent = Column(Text)

class ThreatIntelligence(Base):
    """Model for storing known threat signatures"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    file_hash = Column(String(64), unique=True, index=True)
    threat_type = Column(String(50))  # 'rat', 'stealer', 'trojan', etc.
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    confidence_score = Column(Float)  # 0.0 to 1.0
    source = Column(String(100))  # 'community', 'automated', 'manual'
    is_active = Column(Boolean, default=True)

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """Create all tables"""
    Base.metadata.create_all(bind=engine)

def init_db():
    """Initialize database with tables"""
    create_tables()
    print("✅ Database tables created successfully")

if __name__ == "__main__":
    init_db()