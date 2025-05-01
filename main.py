from fastapi import FastAPI, UploadFile, File
from ml.predict import predict_file
from fastapi.middleware.cors import CORSMiddleware

import json
import re
from dataset_logger import log_scanned_jar, log_scanned_jar_features

# Regex to detect Discord webhooks
discord_webhook_regex = re.compile(r"https:\/\/(canary\.|ptb\.)?discord(app)?\.com\/api\/webhooks\/[0-9]+\/[\w-]+")

app = FastAPI(title="Minecraft Security Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "https://security-frontend-eta.vercel.app/"],  # Your React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    
)

@app.get("/")
def root():
    return {"message": "Welcome to the Minecraft Security Detector API"}

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
async def scan_jar(file: UploadFile = File(...)):
    import zipfile
    import tempfile
    import os

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jar") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    suspicious_hits = []
    suspicious_keywords = ["token", "webhook", "session", "auth", "mojang", "discord", "stealer"]
    safe_file_keywords = ["mcmod", "manifest", "meta-inf", "pack.mcmeta", "optifine", "font", "logo"]

    # ✅ Feature counters
    num_class_files = 0
    num_txt_files = 0
    num_json_files = 0
    has_token_string = 0
    has_discord_webhook = 0

    try:
        with zipfile.ZipFile(tmp_path, 'r') as jar:
            for name in jar.namelist():
                lower_name = name.lower()

                # Skip safe known files
                if any(safe in lower_name for safe in safe_file_keywords):
                    continue

                if lower_name.endswith(".class"):
                    num_class_files += 1
                elif lower_name.endswith(".txt"):
                    num_txt_files += 1
                elif lower_name.endswith(".json"):
                    num_json_files += 1

                # Read and scan content
                if lower_name.endswith((".class", ".json", ".txt", ".cfg")):
                    try:
                        content = jar.read(name).decode("utf-8", errors="ignore").lower()

                        # Regex: Discord webhook URLs
                        matches = discord_webhook_regex.findall(content)
                        for match in matches:
                            has_discord_webhook = 1
                            suspicious_hits.append({
                                "file": name,
                                "keyword": "discord_webhook",
                                "match": match
                            })

                        if "discord" in content and "webhook" in content:
                            has_discord_webhook = 1
                            suspicious_hits.append({"file": name, "keyword": "discord_webhook"})

                        # Keyword detection
                        for keyword in suspicious_keywords:
                            if keyword in content:
                                suspicious_hits.append({"file": name, "keyword": keyword})
                                if keyword == "token":
                                    has_token_string = 1
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        return {"error": "Not a valid .jar file"}

    # Compute size in KB
    size_kb = round(os.path.getsize(tmp_path) / 1024, 2)

    # ✅ Predict using ML model
    features = {
        "num_class_files": num_class_files,
        "num_txt_files": num_txt_files,
        "num_json_files": num_json_files,
        "has_token_string": has_token_string,
        "has_discord_webhook": has_discord_webhook,
        "size_kb": size_kb
    }
    prediction_result = predict_file(features)
    print("DEBUG: prediction_result =", prediction_result)

    # Optional manual rule
    is_malicious = prediction_result["prediction"] == "malicious"
    print(f"Logging {file.filename} → {'MALICIOUS' if is_malicious else 'SAFE'}")
    log_scanned_jar(tmp_path, is_malicious, file.filename)
    log_scanned_jar_features(file.filename, features, is_malicious) 

    return {
        "filename": file.filename,
        "features": features,
        "suspicious_hits": suspicious_hits,
        "is_malicious": is_malicious,
        "ml_prediction": prediction_result
    }

import os
import pandas as pd
import numpy as np
from fastapi.responses import JSONResponse

@app.get("/scan-history/")
def get_scan_history():
    try:
        if not os.path.exists("jar_features.csv"):
            return []

        df = pd.read_csv("jar_features.csv")

        if "filename" not in df.columns:
            return []

        df = df.drop_duplicates(subset="filename", keep="last")

        # Replace inf/-inf and convert NaN to None (JSON-safe)
        df = df.replace([np.inf, -np.inf], np.nan)
        records = df.where(pd.notnull(df), None).to_dict(orient="records")

        print("DEBUG: final scan history preview")
        print(df[["filename", "label"]].tail())

        return JSONResponse(content=records)

    except Exception as e:
        print(f"Error reading scan history: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
