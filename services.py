#!/usr/bin/env python3
"""
Database and S3 services for RAT detector
"""

import hashlib
import os
import time
from datetime import datetime
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session
from database import ScanResult, ThreatIntelligence
from dotenv import load_dotenv

load_dotenv()

class FileHashService:
    """Service for computing file hashes"""
    
    @staticmethod
    def compute_sha256(file_path: str) -> str:
        """Compute SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

class S3Service:
    """Service for S3 operations"""
    
    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
        self.bucket_safe = os.getenv('S3_BUCKET_SAFE', 'rat-detector-safe-mods')
        self.bucket_malicious = os.getenv('S3_BUCKET_MALICIOUS', 'rat-detector-malicious-mods')
        self.bucket_quarantine = os.getenv('S3_BUCKET_QUARANTINE', 'rat-detector-quarantine')
    
    def upload_to_quarantine(self, file_path: str, filename: str) -> str:
        """Upload file to quarantine bucket"""
        key = f"quarantine/{datetime.utcnow().strftime('%Y/%m/%d')}/{filename}"
        try:
            self.s3_client.upload_file(file_path, self.bucket_quarantine, key)
            return f"s3://{self.bucket_quarantine}/{key}"
        except ClientError as e:
            raise Exception(f"Failed to upload to quarantine: {e}")
    
    def move_to_final_bucket(self, quarantine_path: str, filename: str, is_malicious: bool) -> str:
        """Move file from quarantine to safe/malicious bucket"""
        # Parse quarantine path
        bucket = quarantine_path.split('/')[2]
        key = '/'.join(quarantine_path.split('/')[3:])
        
        # Determine destination
        dest_bucket = self.bucket_malicious if is_malicious else self.bucket_safe
        dest_key = f"{'malicious' if is_malicious else 'safe'}/{datetime.utcnow().strftime('%Y/%m/%d')}/{filename}"
        
        try:
            # Copy to destination bucket
            copy_source = {'Bucket': bucket, 'Key': key}
            self.s3_client.copy_object(CopySource=copy_source, Bucket=dest_bucket, Key=dest_key)
            
            # Delete from quarantine
            self.s3_client.delete_object(Bucket=bucket, Key=key)
            
            return f"s3://{dest_bucket}/{dest_key}"
        except ClientError as e:
            raise Exception(f"Failed to move file: {e}")

class DatabaseService:
    """Service for database operations"""
    
    @staticmethod
    def save_scan_result(
        db: Session,
        filename: str,
        file_hash: str,
        prediction: str,
        probability_malicious: float,
        features: Dict[str, Any],
        file_size: int,
        s3_location: str,
        processing_time: float,
        user_ip: str = None,
        user_agent: str = None
    ) -> ScanResult:
        """Save scan result to database"""
        
        scan_result = ScanResult(
            filename=filename,
            file_hash=file_hash,
            prediction=prediction,
            probability_malicious=probability_malicious,
            features=features,
            file_size=file_size,
            s3_location=s3_location,
            processing_time_seconds=processing_time,
            user_ip=user_ip,
            user_agent=user_agent
        )
        
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        return scan_result
    
    @staticmethod
    def get_scan_by_hash(db: Session, file_hash: str) -> Optional[ScanResult]:
        """Get existing scan result by file hash"""
        return db.query(ScanResult).filter(ScanResult.file_hash == file_hash).first()
    
    @staticmethod
    def add_threat_intelligence(
        db: Session,
        file_hash: str,
        threat_type: str,
        confidence_score: float,
        source: str = "automated"
    ) -> ThreatIntelligence:
        """Add threat intelligence entry"""
        
        threat = ThreatIntelligence(
            file_hash=file_hash,
            threat_type=threat_type,
            confidence_score=confidence_score,
            source=source
        )
        
        db.add(threat)
        db.commit()
        db.refresh(threat)
        return threat
    
    @staticmethod
    def is_known_threat(db: Session, file_hash: str) -> Optional[ThreatIntelligence]:
        """Check if file hash is a known threat"""
        return db.query(ThreatIntelligence).filter(
            ThreatIntelligence.file_hash == file_hash,
            ThreatIntelligence.is_active == True
        ).first()

# Service instances
file_hash_service = FileHashService()
s3_service = S3Service()
db_service = DatabaseService()