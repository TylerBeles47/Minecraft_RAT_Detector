import pandas as pd
import joblib
import os
import boto3
from botocore.exceptions import ClientError

# Global variables for lazy loading
model = None
feature_names = None
scaler = None

def load_model():
    """Lazy load the ML model from local file or S3"""
    global model, feature_names, scaler
    if model is None:
        model_path = "models/strong_detector.pkl"
        
        # Try to load from local file first
        if not os.path.exists(model_path):
            print("Local model not found, attempting S3 download...")
            download_model_from_s3(model_path)
        
        try:
            model, feature_names, scaler = joblib.load(model_path)
            print("✅ ML model loaded successfully")
        except FileNotFoundError:
            print("❌ ML model file not found after S3 download attempt")
            raise
        except Exception as e:
            print(f"❌ Failed to load ML model: {e}")
            raise

def download_model_from_s3(local_path):
    """Download model from S3 bucket"""
    try:
        bucket_name = os.getenv("MODEL_S3_BUCKET")
        if not bucket_name:
            print("MODEL_S3_BUCKET environment variable not set")
            return
            
        s3_client = boto3.client('s3')
        s3_key = "models/strong_detector.pkl"
        
        print(f"Downloading model from s3://{bucket_name}/{s3_key}")
        s3_client.download_file(bucket_name, s3_key, local_path)
        print("✅ Model downloaded from S3")
        
    except ClientError as e:
        print(f"❌ Failed to download model from S3: {e}")
    except Exception as e:
        print(f"❌ Error downloading model: {e}")

def predict_file(jar_features: dict) -> dict:
    # Load model if not already loaded
    try:
        load_model()
    except FileNotFoundError:
        # Return safe prediction if model is missing (for health checks)
        return {
            "prediction": "safe",
            "probability_malicious": 0.0,
            "error": "ML model not available"
        }
    
    # Create a DataFrame from the features, ensuring all expected columns are present
    X = pd.DataFrame([jar_features], columns=feature_names)

    # Fill any missing columns with 0s (important for consistent feature set)
    for col in feature_names:
        if col not in X.columns:
            X[col] = 0

    # Ensure the order of columns is consistent with training
    X = X[feature_names]

    # Scale the features using the loaded scaler
    X_scaled = scaler.transform(X)

    # Handle edge case: model trained on only 1 class
    if model.n_classes_ == 1:
        only_class = model.classes_[0]
        prob_malicious = 1.0 if only_class == 1 else 0.0
    else:
        prob_malicious = model.predict_proba(X_scaled)[0][1]

    # Check for known legitimate mod patterns before applying threshold
    minecraft_api_usage = jar_features.get("minecraft_api_usage", 0)
    has_mod_metadata = jar_features.get("has_mod_metadata", 0)
    legitimate_connections = jar_features.get("legitimate_connections", 0)
    discord_webhook = jar_features.get("discord_webhook", 0)
    
    # Strong legitimacy indicators - likely a real mod
    if (has_mod_metadata and minecraft_api_usage > 0 and legitimate_connections and 
        discord_webhook == 0 and prob_malicious < 0.98):
        label = "safe"
    else:
        # Use higher threshold to reduce false positives
        label = "malicious" if prob_malicious > 0.7 else "safe"

    return {
        "prediction": label,
        "probability_malicious": round(prob_malicious, 4)
    }