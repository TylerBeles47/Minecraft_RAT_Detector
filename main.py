from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import tempfile
import os
import time
import json
import re
from typing import Dict, Any

# Import services
from database import get_db, init_db
from services import file_hash_service, s3_service, db_service
from ml.predict import predict_file
from extract_features import extract_jar_features, decompile_jar_if_needed, extract_decompiled_features

# Regex to detect Discord webhooks
discord_webhook_regex = re.compile(r"https:\/\/(canary\.|ptb\.)?discord(app)?\.com\/api\/webhooks\/[0-9]+\/[\w-]+")

app = FastAPI(
    title="Minecraft RAT Detector API",
    description="Advanced malware detection for Minecraft mods",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "https://security-frontend-orcin.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Templates
templates = Jinja2Templates(directory="templates")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    print("FastAPI application starting up!")
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.methods} {route.path}")
    init_db()  # Initialize database tables

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload", response_class=HTMLResponse)
async def upload_file_web(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Web upload endpoint that returns HTML (matches original Flask app)"""
    start_time = time.time()
    
    # Validate file
    if not file.filename.endswith('.jar'):
        raise HTTPException(status_code=400, detail="Only JAR files are supported")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        filename = file.filename
        file_size = len(content)
        
        # Compute file hash
        file_hash = file_hash_service.compute_sha256(tmp_path)
        
        # Check if already scanned
        existing_scan = db_service.get_scan_by_hash(db, file_hash)
        if existing_scan:
            prediction_label = existing_scan.prediction
            probability = existing_scan.probability_malicious
            print(f"Using cached result for {filename}: {prediction_label}")
        else:
            # Extract features and predict
            decompiled_output_dir = os.path.join('temp_decompiled', os.path.splitext(filename)[0])
            
            if decompile_jar_if_needed(tmp_path, decompiled_output_dir):
                features = extract_decompiled_features(decompiled_output_dir)
                print(f"Extracted features from decompiled code for {filename}: {features}")
            else:
                features = extract_jar_features(tmp_path)
                print(f"Extracted features from JAR for {filename}: {features}")
            
            if not features:
                raise HTTPException(status_code=500, detail="Could not extract features from JAR file")
            
            prediction_result = predict_file(features)
            prediction_label = prediction_result["prediction"]
            probability = float(prediction_result["probability_malicious"])
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Get client info
            client_ip = request.client.host
            user_agent = request.headers.get("user-agent", "")
            
            # Save to database
            db_service.save_scan_result(
                db=db,
                filename=filename,
                file_hash=file_hash,
                prediction=prediction_label,
                probability_malicious=probability,
                features=features,
                file_size=file_size,
                s3_location="",
                processing_time=processing_time,
                user_ip=client_ip,
                user_agent=user_agent
            )
        
        # Store file locally based on prediction
        local_storage_dir = "local_storage/malicious" if prediction_label == "malicious" else "local_storage/safe"
        os.makedirs(local_storage_dir, exist_ok=True)
        
        import shutil
        local_file_path = os.path.join(local_storage_dir, filename)
        shutil.copy2(tmp_path, local_file_path)
        
        print(f"Scan completed: {filename} → {prediction_label.upper()}")
        
        # Return HTML result page (like original Flask app)
        return templates.TemplateResponse("result.html", {
            "request": request,
            "filename": filename,
            "prediction": prediction_label,
            "probability": probability
        })
        
    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if 'decompiled_output_dir' in locals() and os.path.exists(decompiled_output_dir):
            import shutil
            shutil.rmtree(decompiled_output_dir)

@app.get("/health")
def health_check():
    """Health check endpoint that doesn't require database connection"""
    print("Health check endpoint called!")
    try:
        health_status = {
            "status": "healthy", 
            "service": "minecraft-rat-detector", 
            "timestamp": time.time()
        }
        
        # Check database connection (but don't fail if it's down)
        try:
            from database import engine
            if engine is not None:
                with engine.connect() as conn:
                    conn.execute("SELECT 1")
                health_status["database"] = "connected"
            else:
                health_status["database"] = "not_configured"
        except Exception as db_error:
            health_status["database"] = f"error: {str(db_error)}"
        
        return health_status
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/api")
def api_root():
    return {"message": "Welcome to the Minecraft RAT Detector API"}

@app.post("/scan-file/")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    content_str = content.decode("utf-8", errors="ignore")
    result = predict_file(content_str)
    return {
        "filename": file.filename,
        "result": result
    }

@app.post("/scan-jar/")
async def scan_jar(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Enhanced scan endpoint with database and S3 integration"""
    start_time = time.time()
    
    # Validate file
    if not file.filename.endswith('.jar'):
        raise HTTPException(status_code=400, detail="Only JAR files are supported")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        filename = file.filename
        file_size = len(content)
        
        # Compute file hash
        file_hash = file_hash_service.compute_sha256(tmp_path)
        
        # Check if already scanned
        existing_scan = db_service.get_scan_by_hash(db, file_hash)
        if existing_scan:
            return {
                "filename": filename,
                "prediction": existing_scan.prediction,
                "probability_malicious": existing_scan.probability_malicious,
                "scan_timestamp": existing_scan.scan_timestamp,
                "cached_result": True
            }
        
        # Check threat intelligence
        known_threat = db_service.is_known_threat(db, file_hash)
        if known_threat:
            # Auto-classify as malicious
            prediction_result = {
                "prediction": "malicious",
                "probability_malicious": known_threat.confidence_score
            }
            features = {"threat_intelligence_match": True}
        else:
            # Local processing (no S3 for development)
            # Extract features and predict
            decompiled_output_dir = os.path.join('temp_decompiled', os.path.splitext(filename)[0])
            
            if decompile_jar_if_needed(tmp_path, decompiled_output_dir):
                features = extract_decompiled_features(decompiled_output_dir)
                print(f"Extracted features from decompiled code for {filename}: {features}")
            else:
                features = extract_jar_features(tmp_path)
                print(f"Extracted features from JAR for {filename}: {features}")
            
            if not features:
                raise HTTPException(status_code=500, detail="Could not extract features from JAR file")
            
            prediction_result = predict_file(features)
            print("DEBUG: prediction_result =", prediction_result)
            
            # For local development, just store in local folders
            is_malicious = prediction_result["prediction"] == "malicious"
            local_storage_dir = "local_storage/malicious" if is_malicious else "local_storage/safe"
            os.makedirs(local_storage_dir, exist_ok=True)
            
            # Copy file to local storage for reference
            import shutil
            local_file_path = os.path.join(local_storage_dir, filename)
            shutil.copy2(tmp_path, local_file_path)
            features["local_storage_path"] = local_file_path
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Get client info
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # Save to database
        scan_result = db_service.save_scan_result(
            db=db,
            filename=filename,
            file_hash=file_hash,
            prediction=prediction_result["prediction"],
            probability_malicious=prediction_result["probability_malicious"],
            features=features,
            file_size=file_size,
            s3_location=features.get("local_storage_path", ""),
            processing_time=processing_time,
            user_ip=client_ip,
            user_agent=user_agent
        )
        
        # Auto-add to threat intelligence if highly malicious
        if (prediction_result["prediction"] == "malicious" and 
            prediction_result["probability_malicious"] > 0.9):
            db_service.add_threat_intelligence(
                db=db,
                file_hash=file_hash,
                threat_type="rat",
                confidence_score=prediction_result["probability_malicious"],
                source="automated"
            )
        
        print(f"Scan completed: {filename} → {prediction_result['prediction'].upper()}")
        
        return {
            "filename": filename,
            "file_hash": file_hash,
            "prediction": prediction_result["prediction"],
            "probability_malicious": prediction_result["probability_malicious"],
            "processing_time_seconds": round(processing_time, 2),
            "scan_id": scan_result.id,
            "cached_result": False
        }
        
    finally:
        # Clean up temp files
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if 'decompiled_output_dir' in locals() and os.path.exists(decompiled_output_dir):
            import shutil
            shutil.rmtree(decompiled_output_dir)

import os
import pandas as pd
import numpy as np
from fastapi.responses import JSONResponse

@app.get("/scan-history/")
def get_scan_history():
    try:
        if not os.path.exists("jar_features.csv"):
            return JSONResponse(content=[])

        df = pd.read_csv("jar_features.csv")

        if "filename" not in df.columns:
            return JSONResponse(content=[])

        df = df.drop_duplicates(subset="filename", keep="last")

        # Replace inf and -inf with NaN, then fill all NaN with 0.0
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0.0)  # or use .fillna(value=None) if you prefer nulls

        print("DEBUG: final scan history preview")
        print(df[["filename", "label"]].tail())

        records = df.to_dict(orient="records")
        return JSONResponse(content=records)

    except Exception as e:
        print(f"Error reading scan history: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
