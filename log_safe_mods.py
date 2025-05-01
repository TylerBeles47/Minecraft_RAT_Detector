



import os
from dataset_logger import log_scanned_jar_features
from extract_features import extract_jar_features  # Adjust if your function is in a different file

SAFE_MODS_DIR = "/home/tbeles/minecraft_security_backend/dataset/safe"

def log_safe_mods():
    if not os.path.exists(SAFE_MODS_DIR):
        print(f"❌ Folder not found: {SAFE_MODS_DIR}")
        return

    jar_files = [f for f in os.listdir(SAFE_MODS_DIR) if f.endswith(".jar")]

    if not jar_files:
        print("❌ No .jar files found in safe_mods folder.")
        return

    for jar_file in jar_files:
        jar_path = os.path.join(SAFE_MODS_DIR, jar_file)
        print(f"🔍 Scanning: {jar_file}")

        features = extract_jar_features(jar_path)

        if not features:
            print(f"❌ Could not extract features from {jar_file}")
            continue

        # Extract and remove filename from feature dict (already passed separately)
        filename = features.pop("filename", jar_file)

        # ✅ Log as SAFE (label = 0)
        log_scanned_jar_features(filename, features, is_malicious=False)
        print(f"✅ Logged SAFE mod: {filename}")

if __name__ == "__main__":
    log_safe_mods()
