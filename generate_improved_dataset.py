#!/usr/bin/env python3
"""
Generate dataset with IMPROVED features to reduce false positives
Combines the new behavioral analysis with robust multiprocessing
"""

import os
import pandas as pd
import multiprocessing
from multiprocessing.pool import TimeoutError
from tqdm import tqdm
from extract_features import extract_jar_features, extract_decompiled_features, decompile_jar_if_needed
import logging

# Configure logging
logging.basicConfig(filename='processing_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

TIMEOUT_SECONDS = 45  # Timeout for processing each mod

def process_mod_with_timeout(args):
    """Process a single mod with timeout handling"""
    import signal
    
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Processing timed out after {TIMEOUT_SECONDS} seconds")
    
    mod_path, label = args
    
    # Set up timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(TIMEOUT_SECONDS)
    
    try:
        if os.path.isdir(mod_path):
            # Use improved feature extraction
            features = extract_decompiled_features(mod_path)
            features["label"] = label
            logging.info(f"Successfully processed {mod_path}")
            signal.alarm(0)  # Cancel timeout
            return features
        elif mod_path.endswith('.jar'):
            # Handle JAR files by decompiling first
            mod_name = os.path.splitext(os.path.basename(mod_path))[0]
            decompiled_dir = os.path.join("temp_decompiled", mod_name)
            
            if decompile_jar_if_needed(mod_path, decompiled_dir):
                features = extract_decompiled_features(decompiled_dir)
            else:
                # Fallback to direct JAR analysis
                features = extract_jar_features(mod_path)
            
            features["label"] = label
            logging.info(f"Successfully processed JAR {mod_path}")
            
            # Clean up temp directory
            import shutil
            if os.path.exists(decompiled_dir):
                shutil.rmtree(decompiled_dir)
            
            signal.alarm(0)  # Cancel timeout
            return features
    except TimeoutError as e:
        logging.warning(f"Timeout processing {mod_path}: {e}")
        signal.alarm(0)  # Cancel timeout
        return None
    except Exception as e:
        logging.error(f"Error processing {mod_path}: {e}")
        signal.alarm(0)  # Cancel timeout
        return None
    
    signal.alarm(0)  # Cancel timeout
    return None

def main():
    """Generate improved dataset with balanced samples"""
    
    # Dataset folders
    SAFE_MODS_DIR = "safe_mods"
    MALICIOUS_MODS_DIR = "malicious_samples400"
    
    all_mods_to_process = []
    
    # Collect safe decompiled mods
    if os.path.exists(SAFE_MODS_DIR):
        for mod_name in os.listdir(SAFE_MODS_DIR):
            mod_path = os.path.join(SAFE_MODS_DIR, mod_name)
            if os.path.isdir(mod_path):
                all_mods_to_process.append((mod_path, 0))  # 0 for safe
    
    # Collect malicious samples
    if os.path.exists(MALICIOUS_MODS_DIR):
        for mod_name in os.listdir(MALICIOUS_MODS_DIR):
            mod_path = os.path.join(MALICIOUS_MODS_DIR, mod_name)
            if os.path.isdir(mod_path) or mod_path.endswith('.jar'):
                all_mods_to_process.append((mod_path, 1))  # 1 for malicious
    
    # Count samples by label for summary
    safe_count = sum(1 for _, label in all_mods_to_process if label == 0)
    malicious_count = sum(1 for _, label in all_mods_to_process if label == 1)
    
    print("🔍 IMPROVED DATASET GENERATION")
    print("=" * 50)
    print(f"📊 Dataset composition:")
    print(f"  Safe samples: {safe_count}")
    print(f"  Malicious samples: {malicious_count}")
    print(f"  Total samples: {len(all_mods_to_process)}")
    if len(all_mods_to_process) > 0:
        print(f"  Split: {safe_count/len(all_mods_to_process)*100:.1f}% safe / {malicious_count/len(all_mods_to_process)*100:.1f}% malicious")
    print(f"✨ Using IMPROVED features to reduce false positives")
    print()
    
    # Create temp directory for JAR decompilation
    os.makedirs("temp_decompiled", exist_ok=True)
    
    # Process mods in parallel
    data = []
    if all_mods_to_process:
        with multiprocessing.Pool() as pool:
            results = []
            for mod_args in all_mods_to_process:
                results.append(pool.apply_async(process_mod_with_timeout, (mod_args,)))
            
            for i, result in enumerate(tqdm(results, total=len(all_mods_to_process), desc="Processing mods")):
                mod_path, _ = all_mods_to_process[i]
                try:
                    processed_data = result.get(timeout=TIMEOUT_SECONDS)
                    if processed_data is not None:
                        data.append(processed_data)
                except TimeoutError:
                    logging.warning(f"Skipping {mod_path} due to timeout after {TIMEOUT_SECONDS} seconds.")
                except Exception as e:
                    logging.error(f"Error processing {mod_path}: {e}")
    
    # Clean up temp directory
    import shutil
    if os.path.exists("temp_decompiled"):
        shutil.rmtree("temp_decompiled")
    
    # Create DataFrame
    if data:
        df = pd.DataFrame(data)
        
        # Fill NaN values with 0
        df = df.fillna(0)
        
        # Save to CSV
        df.to_csv("jar_features_improved.csv", index=False)
        
        print("\n🎉 DATASET GENERATED SUCCESSFULLY!")
        print(f"✅ Saved to: jar_features_improved.csv")
        print(f"📊 Final samples: {len(df)}")
        print(f"   Safe: {sum(df['label'] == 0)}")
        print(f"   Malicious: {sum(df['label'] == 1)}")
        
        # Show some of the new improved features
        print(f"\n🔍 New behavioral features included:")
        new_features = [
            "discord_webhook", "suspicious_urls", "legitimate_connections",
            "has_mod_metadata", "minecraft_api_usage", "obfuscation_tools"
        ]
        
        for feat in new_features:
            if feat in df.columns:
                non_zero = sum(df[feat] != 0)
                print(f"   {feat}: {non_zero} samples with this feature")
        
        print(f"\n💡 Use this dataset with train_model.py for improved RAT detection!")
        
    else:
        print("❌ No data was processed successfully. Check your directories and logs.")

if __name__ == "__main__":
    main()