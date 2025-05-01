import pandas as pd
import joblib

# Load model and feature names
model, feature_names = joblib.load("models/strong_detector.pkl")

def predict_file(jar_features: dict) -> dict:
    X = pd.DataFrame([jar_features], columns=feature_names)

    # Handle edge case: model trained on only 1 class
    if model.n_classes_ == 1:
        only_class = model.classes_[0]
        prob_malicious = 1.0 if only_class == 1 else 0.0
    else:
        prob_malicious = model.predict_proba(X)[0][1]

    label = "malicious" if prob_malicious > 0.85 else "safe"

    return {
        "prediction": label,
        "probability_malicious": round(prob_malicious, 4)
    }