import zipfile
import os
import math

# Basic keyword list (can expand later)
suspicious_keywords = ["token", "webhook", "session", "auth", "mojang", "discord", "stealer"]

# Your custom rat strings
rat_signatures = ["func_111286_b", "discòrd", "requestv2"]

def calc_entropy(data: str) -> float:
    """Estimates Shannon entropy of a string"""
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(data)]
    return -sum(p * math.log(p, 2) for p in prob)

def extract_jar_features(jar_path):
    features = {
        "filename": os.path.basename(jar_path),
        "num_class_files": 0,
        "num_files_total": 0,
        "avg_class_name_length": 0,
        "suspicious_keywords": 0,
        "has_discord_webhook": 0,
        "entropy_score": 0,
    }

    # Add rat signature placeholders
    for sig in rat_signatures:
        features[sig] = 0

    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            class_lengths = []
            suspicious_count = 0
            entropy_scores = []

            for name in jar.namelist():
                features["num_files_total"] += 1
                if name.endswith(".class"):
                    features["num_class_files"] += 1
                    class_lengths.append(len(name))
                try:
                    content = jar.read(name).decode("utf-8", errors="ignore").lower()
                    entropy_scores.append(calc_entropy(content))

                    # Count suspicious keywords
                    for keyword in suspicious_keywords:
                        if keyword in content:
                            suspicious_count += 1

                    if "discord.com/api/webhooks/" in content:
                        features["has_discord_webhook"] = 1

                    # Flag custom rat terms
                    for sig in rat_signatures:
                        if sig.lower() in content:
                            features[sig] = 1

                except:
                    continue

            features["avg_class_name_length"] = (
                sum(class_lengths) / len(class_lengths) if class_lengths else 0
            )
            features["suspicious_keywords"] = suspicious_count
            features["entropy_score"] = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0

    except zipfile.BadZipFile:
        print(f"❌ Not a valid .jar file: {jar_path}")

    return features
