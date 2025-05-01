# dataset_logger.py

import pandas as pd
import os
from datetime import datetime

def log_scanned_jar(file_path, is_malicious, filename):
    """
    Logs a basic history of scanned .jar files with verdict and timestamp.
    Useful for tracking scanned files.
    """
    log_file = "scan_log.csv"
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "filename": filename,
        "file_path": file_path,
        "is_malicious": int(is_malicious)
    }

    if os.path.exists(log_file):
        df = pd.read_csv(log_file)
        df = pd.concat([df, pd.DataFrame([entry])], ignore_index=True)
    else:
        df = pd.DataFrame([entry])

    df.to_csv(log_file, index=False)


def log_scanned_jar_features(filename, features: dict, is_malicious: bool):
    """
    Appends extracted .jar features and label to the ML dataset.
    Used for training/retraining the model.
    """
    row = features.copy()
    row["filename"] = filename
    row["label"] = int(is_malicious)

    file_path = "jar_features.csv"
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
        df.drop_duplicates(subset="filename", keep="last", inplace=True)
    else:
        df = pd.DataFrame([row])

    df.to_csv(file_path, index=False)

