import pandas as pd
import joblib
import os
from sklearn.model_selection import KFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, make_scorer
from sklearn.preprocessing import StandardScaler
import numpy as np

# Load improved dataset with new behavioral features
df = pd.read_csv("jar_features_improved.csv")

# Define expected features - updated with new behavioral analysis features
features = [
    # Basic file metrics
    "num_class_files",
    "num_files_total", 
    "filename_length",
    "has_dat_file",
    "class_to_total_ratio",
    "entropy_score",
    
    # New behavioral analysis features
    "discord_webhook",
    "suspicious_urls", 
    "legitimate_connections",
    "data_collection_patterns",
    "token_access_patterns",
    "http_operations_count",
    "base64_usage",
    "network_to_game_ratio",
    
    # Code structure features
    "avg_class_name_length",
    "avg_method_name_length", 
    "short_class_names_ratio",
    "short_method_names_ratio",
    "total_classes",
    "total_methods",
    
    # Legitimacy indicators
    "has_mod_metadata",
    "minecraft_api_usage",
    "obfuscation_tools", 
    "suspicious_file_operations",
    "filename_entropy",
    
    # Legacy features (keeping for compatibility)
    "uses_reflection",
    "executes_commands",
    "func_111286_b",
    "discòrd", 
    "requestv2",
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

# Ensure all feature columns are numeric
for col in features:
    X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Hyperparameter tuning using GridSearchCV
param_grid = {
    'n_estimators': [100, 200, 300, 400, 500],
    'max_depth': [10, 20, 30, 40, 50, None]
}

# With balanced data, we can use standard accuracy scoring
scorer = make_scorer(accuracy_score)

# Remove class_weight='balanced' since data is now balanced
grid_search = GridSearchCV(estimator=RandomForestClassifier(random_state=42), param_grid=param_grid, cv=5, scoring=scorer, n_jobs=-1)
grid_search.fit(X_scaled, y)

best_model = grid_search.best_estimator_
print(f"\nBest parameters found: {grid_search.best_params_}")
print(f"Best cross-validation score: {grid_search.best_score_:.4f}")

# K-Fold Cross-Validation with the best model
kf = KFold(n_splits=5, shuffle=True, random_state=42) # 5 splits

all_accuracies = []
all_reports = []
feature_importances = np.zeros(len(features))

for fold, (train_index, test_index) in enumerate(kf.split(X_scaled)):
    print(f"\n--- Fold {fold + 1} ---")
    X_train, X_test = X_scaled[train_index], X_scaled[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]

    # Train Random Forest model with best parameters
    model = best_model
    model.fit(X_train, y_train)

    # Evaluate model performance
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)
    print(f"Classification Report for Fold {fold + 1}:\n{classification_report(y_test, y_pred)}")

    all_accuracies.append(accuracy)
    all_reports.append(report)
    feature_importances += model.feature_importances_

print("\n--- Cross-Validation Results ---")
print(f"Average Accuracy: {np.mean(all_accuracies):.4f}")

# Average feature importances
feature_importances /= kf.n_splits
importance_df = pd.DataFrame({
    'Feature': features,
    'Importance': feature_importances
}).sort_values(by='Importance', ascending=False)

print("\n--- Feature Importances ---")
print(importance_df)

# Save the best model
os.makedirs("models", exist_ok=True)
joblib.dump((best_model, features, scaler), "models/strong_detector.pkl")
print("\n📦 Model saved to models/strong_detector.pkl")