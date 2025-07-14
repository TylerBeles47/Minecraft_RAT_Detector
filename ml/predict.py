import pandas as pd
import joblib
import os

# Load model, feature names, and scaler
model, feature_names, scaler = joblib.load("models/strong_detector.pkl")

def predict_file(jar_features: dict) -> dict:
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