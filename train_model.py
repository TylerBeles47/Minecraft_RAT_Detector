import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load structured dataset
df = pd.read_csv("jar_features.csv")

# Define expected features
features = [
    "num_class_files",
    "num_txt_files",
    "num_json_files",
    "has_token_string",
    "has_discord_webhook",
    "size_kb"
]

# ✅ Fill in any missing expected columns with 0
for col in features:
    if col not in df.columns:
        print(f"⚠️  Column '{col}' missing. Filling with 0s.")
        df[col] = 0

# Drop rows with missing labels or invalid values
df = df.dropna()
df = df[df["label"].isin([0, 1])]

# Extract feature matrix and target vector
X = df[features]
y = df["label"]

# Split data into train/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model performance
y_pred = model.predict(X_test)
print("✅ Model trained successfully.")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save model and feature list
os.makedirs("models", exist_ok=True)
joblib.dump((model, features), "models/strong_detector.pkl")
print("📦 Model saved to models/strong_detector.pkl")
