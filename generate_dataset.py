import os
import pandas as pd
from extract_features import extract_jar_features

# Path to dataset folders
DATA_DIR = "dataset"

# Labels
folders = [("safe", 0), ("malicious", 1)]

data = []

for folder_name, label in folders:
    folder_path = os.path.join(DATA_DIR, folder_name)
    if not os.path.exists(folder_path):
        continue

    for filename in os.listdir(folder_path):
        if filename.endswith(".jar"):
            file_path = os.path.join(folder_path, filename)
            features = extract_jar_features(file_path)
            features["label"] = label
            data.append(features)

# Create DataFrame
df = pd.DataFrame(data)

# Save to CSV
df.to_csv("jar_features.csv", index=False)
print("✅ Dataset saved to jar_features.csv with", len(df), "samples")
