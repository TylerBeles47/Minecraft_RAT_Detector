import zipfile
import os
import math
import re
from collections import Counter

# Refined malicious patterns - more specific to actual threats
malicious_patterns = {
    "token_stealing": ["authtoken", "sessiontoken", "bearertoken", "accesstoken"],
    "data_exfiltration": ["webhook", "stealer", "grab", "steal", "exfil"],
    "obfuscation": ["zelix", "proguard", "allatori", "obfuscate"],
    "suspicious_domains": ["bit.ly", "tinyurl", "pastebin", "hastebin"],
    "rat_signatures": ["func_111286_b", "discòrd", "requestv2"]
}

# Legitimate gaming domains and APIs
legitimate_domains = [
    "hypixel.net", "mojang.com", "minecraft.net", "curseforge.com", 
    "modrinth.com", "fabricmc.net", "minecraftforge.net", "spongeproject.org"
]

# Common Minecraft mod APIs (legitimate)
minecraft_apis = [
    "net.minecraft", "net.minecraftforge", "net.fabricmc", 
    "cpw.mods.fml", "org.spongepowered"
]

def calc_entropy(data: str) -> float:
    """Estimates Shannon entropy of a string"""
    if not data:
        return 0
    
    # Use collections.Counter for efficient frequency counting
    counts = Counter(data)
    total_length = len(data)
    
    prob = [float(count) / total_length for count in counts.values()]
    return -sum(p * math.log(p, 2) for p in prob)

def analyze_code_structure(content: str) -> dict:
    """Analyze code structure for obfuscation indicators"""
    
    # Find class names
    class_names = re.findall(r'class\s+([A-Za-z_][A-Za-z0-9_]*)', content)
    method_names = re.findall(r'def\s+([A-Za-z_][A-Za-z0-9_]*)', content) + \
                  re.findall(r'public\s+\w+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', content)
    
    # Calculate name characteristics
    avg_class_name_length = sum(len(name) for name in class_names) / max(len(class_names), 1)
    avg_method_name_length = sum(len(name) for name in method_names) / max(len(method_names), 1)
    
    # Count single-character names (obfuscation indicator)
    short_class_names = sum(1 for name in class_names if len(name) <= 2)
    short_method_names = sum(1 for name in method_names if len(name) <= 2)
    
    return {
        "avg_class_name_length": avg_class_name_length,
        "avg_method_name_length": avg_method_name_length,
        "short_class_names_ratio": short_class_names / max(len(class_names), 1),
        "short_method_names_ratio": short_method_names / max(len(method_names), 1),
        "total_classes": len(class_names),
        "total_methods": len(method_names)
    }

def analyze_network_behavior(content: str) -> dict:
    """Analyze network behavior patterns"""
    content_lower = content.lower()
    
    # Look for suspicious network patterns
    discord_webhook = bool(re.search(r'discord\.com/api/webhooks/\d+/[\w-]+', content_lower))
    
    # Be more specific about suspicious URLs - check context
    suspicious_urls = 0
    for domain in malicious_patterns["suspicious_domains"]:
        if domain in content_lower:
            # Check if it's actually used for data exfiltration, not just mentioned
            domain_contexts = re.findall(f'.{{0,50}}{domain}.{{0,50}}', content_lower)
            for context in domain_contexts:
                if any(op in context for op in ['post', 'send', 'upload', 'submit']):
                    suspicious_urls = 1
                    break
    
    legitimate_connections = any(domain in content_lower for domain in legitimate_domains)
    
    # Check for data exfiltration patterns - be more specific
    data_collection = 0
    for pattern in malicious_patterns["data_exfiltration"]:
        if pattern in content_lower:
            # Check if it's in a suspicious context (not just documentation)
            pattern_contexts = re.findall(f'.{{0,50}}{pattern}.{{0,50}}', content_lower)
            for context in pattern_contexts:
                if any(suspicious in context for suspicious in ['discord.com', 'http', 'send', 'post']):
                    data_collection += 1
                    break
    
    token_access = 0
    for pattern in malicious_patterns["token_stealing"]:
        if pattern in content_lower:
            # Only count if near network/file operations
            pattern_contexts = re.findall(f'.{{0,50}}{pattern}.{{0,50}}', content_lower)
            for context in pattern_contexts:
                if any(suspicious in context for suspicious in ['http', 'file', 'send', 'get']):
                    token_access += 1
                    break
    
    # Network operation complexity
    http_operations = len(re.findall(r'(post|get|put|delete)\s*\(', content_lower))
    base64_usage = len(re.findall(r'base64', content_lower))
    
    return {
        "discord_webhook": 1 if discord_webhook else 0,
        "suspicious_urls": 1 if suspicious_urls else 0,
        "legitimate_connections": 1 if legitimate_connections else 0,
        "data_collection_patterns": data_collection,
        "token_access_patterns": token_access,
        "http_operations_count": http_operations,
        "base64_usage": base64_usage,
        "network_to_game_ratio": min(10.0, http_operations / max(1, sum(1 for api in minecraft_apis if api in content_lower)))
    }

def check_mod_legitimacy(content: str, filename: str) -> dict:
    """Check indicators of legitimate mod vs malicious code"""
    content_lower = content.lower()
    
    # Check for proper mod metadata
    has_mod_metadata = any(meta in content_lower for meta in ["mcmod.info", "fabric.mod.json", "mods.toml"])
    
    # Check for legitimate Minecraft API usage
    minecraft_api_usage = sum(1 for api in minecraft_apis if api in content_lower)
    
    # Check for obfuscation tools
    obfuscation_tools = sum(1 for tool in malicious_patterns["obfuscation"] if tool in content_lower)
    
    # File path analysis - more specific to actual malicious operations
    suspicious_file_ops = len(re.findall(r'(appdata[/\\]roaming[/\\]\.minecraft[/\\]logs|system32[/\\]drivers|windows[/\\]system32[/\\]config)', content_lower))
    
    return {
        "has_mod_metadata": 1 if has_mod_metadata else 0,
        "minecraft_api_usage": minecraft_api_usage,
        "obfuscation_tools": obfuscation_tools,
        "suspicious_file_operations": suspicious_file_ops,
        "filename_entropy": calc_entropy(filename)
    }

def extract_jar_features(jar_path):
    """Extract improved features from JAR file using advanced analysis"""
    features = {
        "filename": os.path.basename(jar_path),
        "num_class_files": 0,
        "num_files_total": 0,
        "filename_length": len(os.path.basename(jar_path)),
        "has_dat_file": 0,
        "class_to_total_ratio": 0,
        "entropy_score": 0,
        
        # New behavioral analysis features
        "discord_webhook": 0,
        "suspicious_urls": 0,
        "legitimate_connections": 0,
        "data_collection_patterns": 0,
        "token_access_patterns": 0,
        "http_operations_count": 0,
        "base64_usage": 0,
        "network_to_game_ratio": 0,
        
        # Code structure features
        "avg_class_name_length": 0,
        "avg_method_name_length": 0,
        "short_class_names_ratio": 0,
        "short_method_names_ratio": 0,
        "total_classes": 0,
        "total_methods": 0,
        
        # Legitimacy indicators
        "has_mod_metadata": 0,
        "minecraft_api_usage": 0,
        "obfuscation_tools": 0,
        "suspicious_file_operations": 0,
        "filename_entropy": 0,
        
        # Legacy features (keeping for compatibility)
        "uses_reflection": 0,
        "executes_commands": 0,
    }

    # Add rat signature placeholders for legacy compatibility
    for sig in malicious_patterns["rat_signatures"]:
        features[sig] = 0

    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            all_content = ""
            entropy_scores = []
            has_dat = False

            # Collect all file contents for comprehensive analysis
            for entry in jar.infolist():
                name = entry.filename
                features["num_files_total"] += 1

                if name.endswith(".class"):
                    features["num_class_files"] += 1
                if name.endswith(".dat"):
                    has_dat = True
                
                try:
                    with jar.open(entry) as file:
                        content = file.read().decode("utf-8", errors="ignore")
                        all_content += content + "\n"
                        entropy_scores.append(calc_entropy(content))

                        # Check for legacy rat signatures
                        for sig in malicious_patterns["rat_signatures"]:
                            if sig.lower() in content.lower():
                                features[sig] = 1

                        # Legacy reflection and command execution
                        if "java.lang.reflect" in content.lower():
                            features["uses_reflection"] = 1
                        if "runtime.exec" in content.lower() or "processbuilder" in content.lower():
                            features["executes_commands"] = 1

                except Exception as e:
                    continue
            
            # Apply new comprehensive analysis
            if all_content:
                # Code structure analysis
                structure_analysis = analyze_code_structure(all_content)
                features.update(structure_analysis)
                
                # Network behavior analysis
                network_analysis = analyze_network_behavior(all_content)
                features.update(network_analysis)
                
                # Legitimacy check
                legitimacy_analysis = check_mod_legitimacy(all_content, os.path.basename(jar_path))
                features.update(legitimacy_analysis)
            
            # Basic metrics
            features["has_dat_file"] = 1 if has_dat else 0
            features["entropy_score"] = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
            if features["num_files_total"] > 0:
                features["class_to_total_ratio"] = features["num_class_files"] / features["num_files_total"]

    except zipfile.BadZipFile:
        pass

    return features

def decompile_jar_if_needed(jar_path, decompiled_output_dir):
    import subprocess
    import shutil

    # Ensure the output directory is clean before attempting decompilation
    if os.path.exists(decompiled_output_dir):
        shutil.rmtree(decompiled_output_dir)
    os.makedirs(decompiled_output_dir, exist_ok=True)

    command = f"java -jar /usr/share/java/procyon-decompiler.jar -o {decompiled_output_dir} {jar_path}"
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True)
        # Verify that files were actually created in the output directory
        if os.listdir(decompiled_output_dir):
            return True
        else:
            print(f"Decompilation command ran, but no files were created in {decompiled_output_dir}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Decompilation failed for {jar_path}: {e.stderr.decode()}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during decompilation for {jar_path}: {e}")
        return False

def extract_decompiled_features(decompiled_path):
    """Extract improved features from decompiled mod directory"""
    features = {
        "filename": os.path.basename(decompiled_path),
        "num_class_files": 0,
        "num_files_total": 0,
        "filename_length": 64,  # Standardize for consistency
        "has_dat_file": 0,
        "class_to_total_ratio": 0,
        "entropy_score": 0,
        
        # New behavioral analysis features
        "discord_webhook": 0,
        "suspicious_urls": 0,
        "legitimate_connections": 0,
        "data_collection_patterns": 0,
        "token_access_patterns": 0,
        "http_operations_count": 0,
        "base64_usage": 0,
        "network_to_game_ratio": 0,
        
        # Code structure features
        "avg_class_name_length": 0,
        "avg_method_name_length": 0,
        "short_class_names_ratio": 0,
        "short_method_names_ratio": 0,
        "total_classes": 0,
        "total_methods": 0,
        
        # Legitimacy indicators
        "has_mod_metadata": 0,
        "minecraft_api_usage": 0,
        "obfuscation_tools": 0,
        "suspicious_file_operations": 0,
        "filename_entropy": 0,
        
        # Legacy features (keeping for compatibility)
        "uses_reflection": 0,
        "executes_commands": 0,
    }

    # Add rat signature placeholders for legacy compatibility
    for sig in malicious_patterns["rat_signatures"]:
        features[sig] = 0

    all_file_contents = []
    entropy_scores = []
    class_names_lengths = []

    # Collect all file contents
    for root, _, files in os.walk(decompiled_path):
        for file in files:
            file_path = os.path.join(root, file)
            features["num_files_total"] += 1

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    all_file_contents.append(content)
                    entropy_scores.append(calc_entropy(content))

                    # Check for legacy rat signatures
                    for sig in malicious_patterns["rat_signatures"]:
                        if sig.lower() in content.lower():
                            features[sig] = 1

                    # Legacy reflection and command execution
                    if "java.lang.reflect" in content.lower():
                        features["uses_reflection"] = 1
                    if "runtime.exec" in content.lower() or "processbuilder" in content.lower():
                        features["executes_commands"] = 1

                    if file.endswith(".java"):  # Decompiled files are .java
                        features["num_class_files"] += 1
                        class_names_lengths.append(len(file))

            except Exception as e:
                continue
    
    # Combine all content for comprehensive analysis
    all_content = "\n".join(all_file_contents)
    
    if all_content:
        # Apply new comprehensive analysis
        structure_analysis = analyze_code_structure(all_content)
        features.update(structure_analysis)
        
        network_analysis = analyze_network_behavior(all_content)
        features.update(network_analysis)
        
        legitimacy_analysis = check_mod_legitimacy(all_content, os.path.basename(decompiled_path))
        features.update(legitimacy_analysis)

    # Basic metrics
    features["entropy_score"] = sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0
    if features["num_files_total"] > 0:
        features["class_to_total_ratio"] = features["num_class_files"] / features["num_files_total"]

    return features
